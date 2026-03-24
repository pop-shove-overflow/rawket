use rawket::tcp::{State, TcpError, TcpFlags};
use crate::{
    assert::{assert_error_fired, assert_state, assert_timestamps_present},
    assert_ok,
    capture::{Dir, ParsedFrameExt},
    harness::setup_tcp_pair,
    packet::{build_tcp_data_with_ts, build_tcp_rst},
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

// ── keepalive_probe_content ───────────────────────────────────────────────────
//
// Keepalive probe: seq = snd_una - 1, payload_len = 0, TSopt present.
// RFC 1122 §4.2.3.6 DISCUSSION: "generally contains SEG.SEQ = SND.NXT-1"
// (descriptive, not normative).
#[test]
fn keepalive_probe_content() -> TestResult {
    use rawket::bridge::LinkProfile;
    let mut pair = setup_tcp_pair()
        .keepalive_idle_ms(50)
        .profile(LinkProfile::leased_line_100m())
        .connect();
    let idle = pair.tcp_cfg.keepalive_idle_ms as i64;

    let snd_una = pair.tcp_a().snd_una();

    pair.advance_both(idle + 10);
    pair.transfer_one();

    let cap = pair.drain_captured();
    let probe = cap.tcp()
        .direction(Dir::AtoB)
        .filter(|f| f.payload_len == 0
            && f.tcp.flags.has(TcpFlags::ACK)
            && !f.tcp.flags.has(TcpFlags::SYN)
            && !f.tcp.flags.has(TcpFlags::RST)
            && !f.tcp.flags.has(TcpFlags::FIN))
        .next()
        .ok_or_else(|| crate::assert::TestFail::new("no keepalive probe"))?;

    // Implementation choice: seq = SND.NXT-1 (= snd_una-1 when no data in flight).
    // RFC 1122 §4.2.3.6 DISCUSSION says "generally contains" this value (non-normative).
    assert_ok!(
        probe.tcp.seq == snd_una.wrapping_sub(1),
        "keepalive probe seq ({}) should be snd_una-1 ({})",
        probe.tcp.seq, snd_una.wrapping_sub(1)
    );

    assert_timestamps_present(&probe, "keepalive probe")?;

    Ok(())
}

// ── keepalive_probe_response ──────────────────────────────────────────────────
//
// RFC 1122 §4.2.3.6: the peer must respond to a keepalive probe with an ACK.
//
// After A sends keepalive probe, B responds with an ACK.
#[test]
fn keepalive_probe_response() -> TestResult {
    use rawket::bridge::LinkProfile;
    let mut pair = setup_tcp_pair()
        .keepalive_idle_ms(50)
        .profile(LinkProfile::leased_line_100m())
        .connect();
    let idle = pair.tcp_cfg.keepalive_idle_ms as i64;

    let snd_una = pair.tcp_a().snd_una();

    // Advance past idle timeout so A sends keepalive probe.
    // transfer_one fires the timer; advance for bridge latency; transfer_one
    // delivers probe to B which sends ACK; one more delivers ACK to A.
    pair.advance_both(idle + 10);
    pair.transfer_one();
    pair.advance_both(25);
    pair.transfer_one();
    pair.transfer_one();

    let cap = pair.drain_captured();
    let probe = cap.tcp()
        .direction(Dir::AtoB)
        .filter(|f| f.payload_len == 0
            && f.tcp.flags.has(TcpFlags::ACK)
            && !f.tcp.flags.has(TcpFlags::SYN)
            && !f.tcp.flags.has(TcpFlags::RST)
            && !f.tcp.flags.has(TcpFlags::FIN)
            && f.tcp.seq == snd_una.wrapping_sub(1))
        .next();
    assert_ok!(probe.is_some(), "A did not send keepalive probe");

    // B's response must ACK with ack = A's snd_una (confirming A's seq space).
    let rcv_nxt = pair.tcp_b().rcv_nxt();
    let response = cap.tcp()
        .direction(Dir::BtoA)
        .with_tcp_flags(TcpFlags::ACK)
        .find(|f| f.tcp.ack == snd_una);
    assert_ok!(
        response.is_some(),
        "B did not respond with ACK = {snd_una} (rcv_nxt={rcv_nxt})"
    );

    Ok(())
}

// ── keepalive_reset_on_ack ────────────────────────────────────────────────────
//
// RFC 1122 §4.2.3.6: receiving data from the peer resets the keepalive timer.
//
// B sends data at 40 ms; A receives it (timer reset).  Another 40 ms: still
// Established and no probes fired.
#[test]
fn keepalive_reset_on_ack() -> TestResult {
    use rawket::bridge::LinkProfile;
    let mut pair = setup_tcp_pair()
        .keepalive_idle_ms(500)
        .keepalive_interval_ms(100)
        .keepalive_count(3)
        .profile(LinkProfile::leased_line_100m())
        .connect();

    // Blackhole B→A so probes go unanswered (will eventually timeout).
    pair.blackhole_to_a();

    // Without data, keepalive timeout = idle + count*interval = 500 + 300 = 800ms.
    // Measure time from connect to Closed.
    let t0 = pair.clock_a.monotonic_ns();
    pair.transfer_while(|p| p.tcp_a(0).state != State::Closed);
    let no_data_timeout = (pair.clock_a.monotonic_ns() - t0) / 1_000_000;

    // Now repeat with data sent at idle/2 to reset the timer.
    pair.clear_impairments();
    let mut pair2 = setup_tcp_pair()
        .keepalive_idle_ms(500)
        .keepalive_interval_ms(100)
        .keepalive_count(3)
        .profile(LinkProfile::leased_line_100m())
        .connect();
    pair2.blackhole_to_a();

    // Send data at idle/2 to reset the keepalive timer.
    pair2.advance_both(250);
    pair2.transfer_one();
    pair2.clear_impairments();
    pair2.tcp_b_mut().send(b"ping")?;
    let b_una = pair2.tcp_b().snd_una();
    pair2.transfer_while(|p| p.tcp_b(0).snd_una() == b_una);
    pair2.blackhole_to_a();

    let t1 = pair2.clock_a.monotonic_ns();
    pair2.transfer_while(|p| p.tcp_a(0).state != State::Closed);
    let with_data_timeout = (pair2.clock_a.monotonic_ns() - t1) / 1_000_000;

    // With data reset, the timeout from t1 should be approximately
    // idle + count*interval = 800ms (timer was reset by the data).
    // Without reset, from t0 it was ~800ms. But with_data starts at ~270ms
    // after connect, so total from connect = ~270 + 800 = ~1070ms.
    // The key: with_data_timeout (from data receipt) ≈ no_data_timeout (from connect).
    // If the timer was NOT reset, with_data_timeout would be much shorter
    // (remaining idle time after the data, not a full idle + probes).
    assert_ok!(
        with_data_timeout >= no_data_timeout * 80 / 100
            && with_data_timeout <= no_data_timeout * 120 / 100,
        "timer not reset: with_data={with_data_timeout}ms, expected ≈{no_data_timeout}ms (±20%)"
    );
    assert_state(pair2.tcp_a(), State::Closed, "A Closed after keepalive timeout")?;

    Ok(())
}

// ── incoming_nonzero_payload_probe_elicits_ack ────────────────────────────────
//
// RFC 9293 §3.8.4: B sends a 1-byte keepalive probe (seq = rcv_nxt - 1).
// A must ACK and must NOT advance rcv_nxt (byte outside window).
#[test]
fn incoming_nonzero_payload_probe_elicits_ack() -> TestResult {
    use rawket::bridge::LinkProfile;
    let mut pair = setup_tcp_pair()
        .profile(LinkProfile::leased_line_100m())
        .connect();

    let rcv_nxt   = pair.tcp_a().rcv_nxt();
    let b_ts_val  = pair.clock_b.monotonic_ms() as u32;
    let b_ts_ecr  = pair.tcp_b().ts_recent();
    let a_snd_nxt = pair.tcp_a().snd_nxt();
    pair.clear_capture();

    let frame = build_tcp_data_with_ts(
        pair.mac_b, pair.mac_a,
        pair.ip_b,  pair.ip_a,
        80, 12345,
        rcv_nxt.wrapping_sub(1), // seq = rcv_nxt - 1 (keepalive probe)
        a_snd_nxt,
        b_ts_val,
        b_ts_ecr,
        &[0xAB],
    );
    pair.inject_to_a(frame);
    pair.transfer();

    let cap = pair.drain_captured();
    let ack_frame = cap.tcp()
        .direction(Dir::AtoB)
        .with_tcp_flags(TcpFlags::ACK)
        .next()
        .ok_or_else(|| crate::assert::TestFail::new("A did not ACK the 1-byte keepalive probe from B"))?;
    // A's ACK must be exactly rcv_nxt (duplicate ACK — probe byte is outside window).
    assert_ok!(
        ack_frame.tcp.ack == rcv_nxt,
        "A's ACK ({}) != rcv_nxt ({rcv_nxt}) — should be duplicate ACK, not advance",
        ack_frame.tcp.ack
    );

    let rcv_nxt_after = pair.tcp_a().rcv_nxt();
    assert_ok!(
        rcv_nxt_after == rcv_nxt,
        "A rcv_nxt advanced ({} → {}) after 1-byte keepalive probe — \
         probe byte must not be delivered",
        rcv_nxt, rcv_nxt_after
    );

    Ok(())
}

// ── keepalive_rst_response ──────────────────────────────────────────────────
//
// RFC 1122 §4.2.3.6: if a keepalive probe elicits a RST (peer has rebooted
// and no longer recognizes the connection), the connection must be aborted.
#[test]
fn keepalive_rst_response() -> TestResult {
    use rawket::bridge::LinkProfile;
    let mut pair = setup_tcp_pair()
        .keepalive_idle_ms(50)
        .profile(LinkProfile::leased_line_100m())
        .connect();
    let idle = pair.tcp_cfg.keepalive_idle_ms as i64;

    let snd_una = pair.tcp_a().snd_una();
    let rcv_nxt = pair.tcp_a().rcv_nxt();

    // Blackhole B→A so B's normal keepalive ACK doesn't arrive.
    pair.blackhole_to_a();

    // Advance past idle to trigger A's keepalive probe.
    pair.advance_both(idle + 10);
    pair.transfer_one();

    // Verify A sent a keepalive probe.
    let cap = pair.drain_captured();
    let probe = cap.all_tcp().from_a()
        .filter(|f| f.payload_len == 0
            && f.tcp.flags.has(TcpFlags::ACK)
            && !f.tcp.flags.has(TcpFlags::SYN)
            && !f.tcp.flags.has(TcpFlags::RST)
            && !f.tcp.flags.has(TcpFlags::FIN)
            && f.tcp.seq == snd_una.wrapping_sub(1))
        .next();
    assert_ok!(probe.is_some(), "A did not send keepalive probe");

    // Clear blackhole and inject RST as if B rebooted.
    pair.clear_impairments();
    let rst = build_tcp_rst(
        pair.mac_b, pair.mac_a,
        pair.ip_b,  pair.ip_a,
        80, 12345,
        rcv_nxt,
    );
    pair.inject_to_a(rst);
    pair.transfer();

    assert_state(pair.tcp_a(), State::Closed, "A must close after RST response to keepalive")?;
    assert_error_fired(pair.tcp_a(), TcpError::Reset, "A error = Reset after keepalive RST")?;

    Ok(())
}

// ── keepalive_first_probe_timing ────────────────────────────────────────────
//
// RFC 1122 §4.2.3.6: keepalives are sent after an idle interval (default
// not less than 2 hours).  This test uses keepalive_idle_ms=100 and verifies
// the probe fires within that window.  The ±20% tolerance and 100ms setting
// are implementation-specific; the RFC does not define this precision.
#[test]
fn keepalive_first_probe_timing() -> TestResult {
    use rawket::bridge::LinkProfile;

    let idle_ms: u64 = 100;
    let mut pair = setup_tcp_pair()
        .keepalive_idle_ms(idle_ms)
        .profile(LinkProfile::leased_line_100m())
        .connect();

    let snd_una = pair.tcp_a().snd_una();
    pair.clear_capture();

    let is_keepalive = |f: &crate::capture::ParsedFrame| -> bool {
        f.tcp.seq == snd_una.wrapping_sub(1) && f.payload_len == 0
            && f.tcp.flags.has(TcpFlags::ACK) && !f.tcp.flags.has(TcpFlags::SYN)
    };

    // Negative check: advance to 80% of idle — no probe should fire.
    pair.advance_both((idle_ms * 80 / 100) as i64);
    pair.transfer_one();

    let cap = pair.drain_captured();
    let premature = cap.tcp().direction(Dir::AtoB).any(|f| is_keepalive(&f));
    assert_ok!(!premature, "keepalive probe fired at 80% of idle_ms — too early");

    // Positive check: advance past the idle timeout — probe must fire.
    pair.clear_capture();
    pair.advance_both((idle_ms * 25 / 100) as i64);  // now at 105% of idle
    pair.transfer_one();

    let cap = pair.drain_captured();
    let fired = cap.tcp().direction(Dir::AtoB).any(|f| is_keepalive(&f));
    assert_ok!(fired, "no keepalive probe at 105% of idle_ms ({idle_ms})");

    Ok(())
}

// ── ack_progress_resets_timer ────────────────────────────────────────────────
//
// RFC 1122 §4.2.3.6: the keepalive timer resets on any connection activity.
// Pure ACK progress (snd_una advances, no payload) counts as activity.
//
// Advance close to the idle deadline, then deliver a pure ACK that advances
// snd_una.  Verify no probe fires for another full idle interval.
#[test]
fn ack_progress_resets_timer() -> TestResult {
    use rawket::bridge::LinkProfile;
    let mut pair = setup_tcp_pair()
        .keepalive_idle_ms(50)
        .profile(LinkProfile::leased_line_100m())
        .connect();
    let idle_ms = pair.tcp_cfg.keepalive_idle_ms as i64;
    let snd_una = pair.tcp_a().snd_una();

    // Send data from A, drive until B's pure ACK advances snd_una.
    pair.tcp_a_mut().send(b"keepalive-ack-test")?;
    pair.clear_capture();
    pair.transfer_while(|p| p.tcp_a(0).snd_una() == snd_una);

    // Verify snd_una advanced via pure ACK (no payload from B).
    let snd_una_after = pair.tcp_a().snd_una();
    assert_ok!(
        snd_una_after > snd_una,
        "snd_una did not advance — ACK not received (was {snd_una}, still {snd_una_after})"
    );

    // Confirm the B→A segments that advanced snd_una were pure ACKs (no payload).
    let cap = pair.drain_captured();
    let b_data = cap.tcp()
        .direction(Dir::BtoA)
        .filter(|f| f.payload_len > 0)
        .count();
    assert_ok!(
        b_data == 0,
        "B sent {b_data} data segment(s) — expected pure ACKs only"
    );

    // Blackhole B→A so no further activity resets the timer.
    pair.blackhole_to_a();

    // The keepalive deadline is at (clock_after_transfer + idle_ms).
    // Use the timer state to find the exact remaining time.
    let remaining_ns = pair.tcp_a().timer_state().keepalive_ns
        .expect("keepalive not armed after ACK progress");
    let remaining_ms = (remaining_ns / 1_000_000) as i64;

    // Helper: detect keepalive probe keyed to snd_una_after.
    let is_probe = |f: &crate::capture::ParsedFrame| {
        f.payload_len == 0
            && f.tcp.flags.has(TcpFlags::ACK)
            && !f.tcp.flags.has(TcpFlags::SYN)
            && !f.tcp.flags.has(TcpFlags::FIN)
            && !f.tcp.flags.has(TcpFlags::RST)
            && f.tcp.seq == snd_una_after.wrapping_sub(1)
    };

    // Negative half: advance to 80% of remaining — no probe yet.
    pair.clear_capture();
    pair.advance_both(remaining_ms * 80 / 100);
    pair.transfer_one();
    let cap = pair.drain_captured();
    let early_probes = cap.tcp().direction(Dir::AtoB).filter(|f| is_probe(f)).count();
    assert_ok!(
        early_probes == 0,
        "keepalive probe fired at 80% of remaining idle — timer not reset"
    );

    // Positive half: advance past the deadline.
    pair.clear_capture();
    pair.advance_both(remaining_ms * 30 / 100); // 80% + 30% = 110%
    pair.transfer_one();
    let cap = pair.drain_captured();
    let probe = cap.tcp().direction(Dir::AtoB).find(|f| is_probe(f));
    assert_ok!(
        probe.is_some(),
        "no keepalive probe after full reset idle interval (expected seq={})",
        snd_una_after.wrapping_sub(1)
    );

    Ok(())
}
