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
// keepalive_idle_ms=50, interval=20, count=3 → timeout at 50 + 3*20 = 110 ms.
// A must close with TcpError::Timeout.
