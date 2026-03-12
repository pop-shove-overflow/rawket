use rawket::{
    bridge::{Impairment, PacketSpec},
    tcp::{State, TcpFlags},
};
use crate::{
    assert::{assert_state, assert_timestamps_present, TestFail},
    assert_ok,
    capture::{Dir, ParsedFrameExt},
    harness::setup_tcp_pair,
    packet::{build_tcp_data, recompute_frame_tcp_checksum},
    TestResult,
};

// ── Helper: inject zero-window ────────────────────────────────────────────────
//
// Sends 1 byte from A (to get seq numbers), then injects a zero-window ACK to
// freeze A's send path.  Advances clock 1000 ms to expire pacing gate.
// Returns `(a_snd_una, b_snd_nxt)` and clears the capture.
fn setup_zero_window(
    pair: &mut crate::harness::TcpSocketPair,
) -> Result<(u32, u32), TestFail> {
    pair.tcp_a_mut().send(b"x")?;
    pair.transfer();

    let cap = pair.drain_captured();
    let (a_first_seq, b_snd_nxt) = {
        let f = cap.tcp()
            .direction(Dir::AtoB)
            .with_data()
            .next()
            .ok_or_else(|| TestFail::new("no AtoB data frame"))?;
        (f.tcp.seq, f.tcp.ack)
    };
    let a_snd_una = a_first_seq + 1; // after "x" is ACKed

    // Build zero-window ACK.
    let mut zw = build_tcp_data(
        pair.mac_b, pair.mac_a,
        pair.ip_b,  pair.ip_a,
        80, 12345,
        b_snd_nxt,
        a_snd_una,
        b"",
    );
    zw[48] = 0; zw[49] = 0; // zero window
    recompute_frame_tcp_checksum(&mut zw);
    pair.inject_to_a(zw);
    pair.transfer_one();

    // Advance clock to expire BBR pacing gate.
    pair.advance_both(1000);
    pair.clear_capture();

    Ok((a_snd_una, b_snd_nxt))
}

// ── zero_window_triggers_persist ─────────────────────────────────────────────
//
// RFC 9293 §3.8.6.1: persist timer arms when receiver advertises zero window.
//
// After zero-window + buffered data, a persist probe must fire within rto_min.
#[test]
fn zero_window_triggers_persist() -> TestResult {
    use rawket::bridge::LinkProfile;
    let mut pair = setup_tcp_pair()
        .profile(LinkProfile::leased_line_100m())
        .connect();
    setup_zero_window(&mut pair)?;

    pair.tcp_a_mut().send(b"world")?;
    let snd_nxt = pair.tcp_a().snd_nxt();

    // Verify persist timer is armed.
    let timers = pair.tcp_a().timer_state();
    assert_ok!(timers.persist_ns.is_some(), "persist not armed after send to zero window: {timers:?}");

    let rto = pair.tcp_a().rto_ms() as i64;
    pair.advance_both(rto + 5);
    pair.transfer_one();

    let cap = pair.drain_captured();
    let probe = cap.tcp()
        .direction(Dir::AtoB)
        .filter(|f| f.payload_len == 1)
        .next()
        .ok_or_else(|| TestFail::new("no persist probe sent"))?;

    // Implementation choice: persist probe uses seq = SND.NXT - 1.
    // RFC 9293 §3.8.6.1 does not specify a particular seq for persist probes.
    let expected_seq = snd_nxt.wrapping_sub(1);
    assert_ok!(
        probe.tcp.seq == expected_seq,
        "persist probe seq ({}) != SND.NXT-1 ({expected_seq})",
        probe.tcp.seq
    );

    Ok(())
}

// ── persist_probe_is_one_byte ─────────────────────────────────────────────────
//
// RFC 9293 §3.8.6.1: persist probe carries one byte to elicit a window update.
//
// The persist probe must carry exactly 1 byte of payload.
#[test]
fn persist_probe_is_one_byte() -> TestResult {
    use rawket::bridge::LinkProfile;
    let mut pair = setup_tcp_pair()
        .profile(LinkProfile::leased_line_100m())
        .connect();
    setup_zero_window(&mut pair)?;

    pair.tcp_a_mut().send(b"world")?;

    let rto = pair.tcp_a().rto_ms() as i64;
    pair.advance_both(rto + 5);
    pair.transfer_one();

    let cap = pair.drain_captured();
    let probe = cap.tcp()
        .direction(Dir::AtoB)
        .with_data()
        .next()
        .ok_or_else(|| TestFail::new("no persist probe found"))?;

    assert_ok!(
        probe.payload_len == 1,
        "persist probe payload_len = {}, expected 1", probe.payload_len
    );

    // RFC 7323: TSopt MUST be present in every non-RST segment.
    assert_timestamps_present(&probe, "persist probe")?;

    Ok(())
}
