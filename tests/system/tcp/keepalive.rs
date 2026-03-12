use std::net::Ipv4Addr;
use rawket::tcp::{State, TcpConfig, TcpError, TcpFlags, TcpSocket};
use crate::{
    assert::{assert_error_fired, assert_state, assert_timestamps_present},
    assert_ok,
    capture::{Dir, ParsedFrameExt},
    harness::{setup_network_pair, setup_tcp_pair},
    packet::build_tcp_data_with_ts,
    TestResult,
};

// ── idle_probe_sequence ───────────────────────────────────────────────────────
//
// RFC 1122 §4.2.3.6: a keepalive probe is sent after the idle timeout
// expires with no data exchange.
//
// After keepalive_idle_ms=50, verify at least 1 keepalive probe
// (ACK with seq = snd_una - 1, no payload).
#[test]
fn idle_probe_sequence() -> TestResult {
    use rawket::bridge::LinkProfile;
    let mut pair = setup_tcp_pair()
        .keepalive_idle_ms(50)
        .profile(LinkProfile::leased_line_100m())
        .connect();

    let idle = pair.tcp_cfg.keepalive_idle_ms as i64;
    let snd_una = pair.tcp_a().snd_una();

    // Verify keepalive timer is armed.
    let timers = pair.tcp_a().timer_state();
    assert_ok!(timers.keepalive_ns.is_some(), "keepalive not armed after connect: {timers:?}");

    // Advance past idle and process the probe.
    pair.advance_both(idle + 10);
    pair.transfer_one();

    let cap = pair.drain_captured();
    let probes = cap.tcp()
        .direction(Dir::AtoB)
        .filter(|f| f.payload_len == 0
            && f.tcp.flags.has(TcpFlags::ACK)
            && !f.tcp.flags.has(TcpFlags::SYN)
            && !f.tcp.flags.has(TcpFlags::RST)
            && !f.tcp.flags.has(TcpFlags::FIN)
            && f.tcp.seq == snd_una.wrapping_sub(1))
        .count();
    assert_ok!(
        probes >= 1,
        "expected ≥1 keepalive probe (seq={}, snd_una={}), got {probes}",
        snd_una.wrapping_sub(1), snd_una
    );

    Ok(())
}

// ── timeout_triggers_error ────────────────────────────────────────────────────
//
// Implementation policy: after exhausting keepalive_count probes without
// response, abort the connection with TcpError::Timeout.  RFC 1122 §4.2.3.6
// does not mandate a specific probe-count timeout; it says "failure to
// respond to any specific probe MUST NOT be interpreted as a dead connection."
//
// keepalive_idle_ms=50, interval=20, count=3 → timeout at 50 + 3*20 = 110 ms.
#[test]
fn timeout_triggers_error() -> TestResult {
    use rawket::bridge::LinkProfile;
    let mut pair = setup_tcp_pair()
        .keepalive_idle_ms(50)
        .keepalive_interval_ms(20)
        .keepalive_count(3)
        .profile(LinkProfile::leased_line_100m())
        .connect();
    let cfg = pair.tcp_cfg.clone();

    let snd_una = pair.tcp_a().snd_una();
    let srtt = pair.tcp_a().srtt_ms();
    let t0 = pair.clock_a.monotonic_ns();

    // Drop B→A so keepalive probes go unanswered.
    pair.blackhole_to_a();

    // Run until keepalive timeout closes the connection.
    pair.transfer_while(|p| p.tcp_a(0).state != State::Closed);

    assert_state(pair.tcp_a(), State::Closed, "A Closed")?;
    assert_error_fired(pair.tcp_a(), TcpError::Timeout, "A error = Timeout")?;

    // Verify timeout timing: idle + count * interval.
    // t0 is after connect(), but the keepalive timer started from the last
    // received handshake segment (up to 1 RTT earlier on a latency link).
    let elapsed_ms = (pair.clock_a.monotonic_ns() - t0) / 1_000_000;
    let expected_ms = cfg.keepalive_idle_ms as u64
        + cfg.keepalive_count as u64 * cfg.keepalive_interval_ms as u64;
    // Allow up to 1 RTT of slack for the handshake-to-t0 offset.
    assert_ok!(
        elapsed_ms >= expected_ms - srtt && elapsed_ms <= expected_ms,
        "keepalive timeout at {elapsed_ms}ms, expected ~{expected_ms}ms \
         (idle={} + {}×interval={})",
        cfg.keepalive_idle_ms, cfg.keepalive_count, cfg.keepalive_interval_ms
    );

    // Verify probe count matches keepalive_count.
    // Filter: seq==snd_una-1 identifies keepalive probes specifically.
    let cap = pair.drain_captured();
    let probes = cap.all_tcp().from_a()
        .filter(|f| f.payload_len == 0
            && f.tcp.flags.has(TcpFlags::ACK)
            && !f.tcp.flags.has(TcpFlags::SYN)
            && !f.tcp.flags.has(TcpFlags::RST)
            && !f.tcp.flags.has(TcpFlags::FIN)
            && f.tcp.seq == snd_una.wrapping_sub(1))
        .count();
    assert_ok!(
        probes == cfg.keepalive_count as usize,
        "expected {} keepalive probes, got {probes} (idle={}, interval={}, count={})",
        cfg.keepalive_count, cfg.keepalive_idle_ms, cfg.keepalive_interval_ms, cfg.keepalive_count
    );

    Ok(())
}

// ── data_resets_timer ─────────────────────────────────────────────────────────
//
// RFC 1122 §4.2.3.6: the keepalive timer resets on any data exchange.
//
// Advancing 40 ms then sending data (ACKed by B) resets A's timer.
// Another 40 ms must leave A still Established (40 < 50 ms idle).
#[test]
fn data_resets_timer() -> TestResult {
    use rawket::bridge::LinkProfile;
    let mut pair = setup_tcp_pair()
        .keepalive_idle_ms(500)
        .profile(LinkProfile::leased_line_100m())
        .connect();
    let idle = pair.tcp_cfg.keepalive_idle_ms as i64;

    // Advance to near keepalive deadline, then send data to reset the timer.
    pair.advance_both(idle - 10);
    pair.transfer_one();
    assert_state(pair.tcp_a(), State::Established, "A still Established before data")?;

    pair.tcp_a_mut().send(b"hello")?;
    // transfer_while stops once B has ACKed the data (snd_una advances).
    let snd_una_before = pair.tcp_a().snd_una();
    pair.transfer_while(|p| p.tcp_a(0).snd_una() == snd_una_before);

    let snd_una = pair.tcp_a().snd_una();

    // Keepalive timer was reset by the data exchange. Advance to
    // 1ms before the idle period — no probe should fire.
    pair.clear_capture();
    pair.clock_a.advance_ns((idle - 1) * 1_000_000);
    pair.clock_b.advance_ns((idle - 1) * 1_000_000);
    pair.transfer_one();

    let is_probe = |f: &crate::capture::ParsedFrame| {
        f.payload_len == 0
            && f.tcp.flags.has(TcpFlags::ACK)
            && !f.tcp.flags.has(TcpFlags::SYN)
            && !f.tcp.flags.has(TcpFlags::RST)
            && !f.tcp.flags.has(TcpFlags::FIN)
            && f.tcp.seq == snd_una.wrapping_sub(1)
    };

    let cap = pair.drain_captured();
    let probes_before = cap.tcp().from_a().filter(|f| is_probe(f)).count();
    assert_ok!(probes_before == 0, "probe fired before reset idle period expired ({probes_before})");

    assert_state(pair.tcp_a(), State::Established, "A Established after data reset timer")?;

    // Now advance 2ms past the deadline — probe should fire.
    pair.advance_both(2);
    pair.transfer_one();

    let cap = pair.drain_captured();
    let probes_after = cap.tcp().from_a().filter(|f| is_probe(f)).count();
    assert_ok!(probes_after >= 1, "no probe fired after full reset idle period");

    Ok(())
}

// ── no_probe_in_non_established ───────────────────────────────────────────────
//
// Implementation choice: keepalive probes only fire in Established.
// RFC 1122 §4.2.3.6 does not explicitly restrict keepalives to Established.
// After B sends FIN and A enters CloseWait, verify no probes fire.
#[test]
fn no_probe_in_non_established() -> TestResult {
    use rawket::bridge::LinkProfile;
    let mut pair = setup_tcp_pair()
        .keepalive_idle_ms(50)
        .profile(LinkProfile::leased_line_100m())
        .connect();

    pair.tcp_b_mut().close()?;
    pair.transfer_while(|p| p.tcp_a(0).state != State::CloseWait);
    assert_state(pair.tcp_a(), State::CloseWait, "A CloseWait")?;
    let snd_una = pair.tcp_a().snd_una();

    pair.clear_capture();

    pair.advance_both(200);
    pair.transfer_one();

    let cap = pair.drain_captured();
    let probes = cap.tcp()
        .direction(Dir::AtoB)
        .filter(|f| f.payload_len == 0
            && f.tcp.flags.has(TcpFlags::ACK)
            && !f.tcp.flags.has(TcpFlags::SYN)
            && !f.tcp.flags.has(TcpFlags::FIN)
            && !f.tcp.flags.has(TcpFlags::RST)
            && f.tcp.seq == snd_una.wrapping_sub(1))
        .count();
    assert_ok!(
        probes == 0,
        "keepalive probes fired in CloseWait ({probes} probes)"
    );

    Ok(())
}

// ── keepalive_disabled_by_default ────────────────────────────────────────────
//
// RFC 1122 §4.2.3.6: keepalive is optional and MUST default to off.
//
// TcpConfig::default() has keepalive_idle_ms = 0 (disabled).  No probes after 60 s.
#[test]
fn keepalive_disabled_by_default() -> TestResult {
    use rawket::bridge::LinkProfile;
    let mut pair = setup_tcp_pair()
        .profile(LinkProfile::leased_line_100m())
        .connect();
    let snd_una = pair.tcp_a().snd_una();
    pair.clear_capture();

    pair.advance_both(60_000);
    pair.transfer_one();

    let cap = pair.drain_captured();
    let probes = cap.tcp()
        .direction(Dir::AtoB)
        .filter(|f| f.payload_len == 0
            && f.tcp.flags.has(TcpFlags::ACK)
            && !f.tcp.flags.has(TcpFlags::SYN)
            && !f.tcp.flags.has(TcpFlags::FIN)
            && !f.tcp.flags.has(TcpFlags::RST)
            && f.tcp.seq == snd_una.wrapping_sub(1))
        .count();
    assert_ok!(
        probes == 0,
        "keepalive probes fired with idle_ms=0 ({probes} probes)"
    );

    Ok(())
}
