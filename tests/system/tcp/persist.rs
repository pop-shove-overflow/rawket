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

// ── persist_exponential_backoff ───────────────────────────────────────────────
//
// RFC 1122 §4.2.2.17: persist timer uses exponential backoff.
//
// Collect 3 probes; verify gaps roughly double (≥1.5× each time).
#[test]
fn persist_exponential_backoff() -> TestResult {
    use rawket::bridge::LinkProfile;
    let mut pair = setup_tcp_pair()
        .profile(LinkProfile::leased_line_100m())
        .connect();
    setup_zero_window(&mut pair)?;

    // Drop all A→B frames so B's non-zero window ACKs cannot reopen the window.
    pair.add_impairment_to_b(Impairment::Drop(PacketSpec::any()));

    pair.tcp_a_mut().send(b"world")?;

    let rto = pair.tcp_a().rto_ms() as i64;

    // Advance through 3 persist probes with exponential backoff.
    pair.advance_both(rto + 5);
    pair.transfer_one();
    pair.advance_both(rto * 2 + 5);
    pair.transfer_one();
    pair.advance_both(rto * 4 + 5);
    pair.transfer_one();

    let cap = pair.drain_captured();
    // Probes may be "dropped" by the impairment we added; use all_tcp() to see them all.
    let probe_times: Vec<u64> = cap.all_tcp()
        .direction(Dir::AtoB)
        .filter(|f| f.payload_len == 1)
        .map(|f| f.ts_ns / 1_000_000) // ns → ms
        .collect();

    assert_ok!(
        probe_times.len() >= 3,
        "expected ≥3 persist probes for backoff test, got {}", probe_times.len()
    );

    let gaps: Vec<u64> = probe_times.windows(2).map(|w| w[1] - w[0]).collect();

    // First inter-probe gap should be ≈ 2*RTO (persist doubles after first probe).
    let rto_ms = rto as u64;
    assert_ok!(
        gaps[0] >= rto_ms * 3 / 2 && gaps[0] <= rto_ms * 5 / 2,
        "first inter-probe gap {} ms not near 2*RTO ({} ms) — expected [{}, {}]",
        gaps[0], rto_ms * 2, rto_ms * 3 / 2, rto_ms * 5 / 2
    );

    // Each subsequent gap should roughly double (≥1.9× previous).
    for i in 1..gaps.len() {
        assert_ok!(
            gaps[i] >= gaps[i - 1] * 19 / 10,
            "persist backoff not exponential: gap[{}]={} ms, gap[{}]={} ms \
             (expected ≥1.9× previous)",
            i - 1, gaps[i - 1], i, gaps[i]
        );
    }

    Ok(())
}

// ── window_open_clears_persist ────────────────────────────────────────────────
//
// RFC 9293 §3.8.6.1: persist timer disarms when window reopens.
//
// After the first probe, inject a window-open ACK.  No further probes should
// appear (persist timer disarmed).
#[test]
fn window_open_clears_persist() -> TestResult {
    use rawket::bridge::LinkProfile;
    let mut pair = setup_tcp_pair()
        .profile(LinkProfile::leased_line_100m())
        .connect();
    let (a_snd_una, b_snd_nxt) = setup_zero_window(&mut pair)?;

    pair.tcp_a_mut().send(b"world")?;

    let rto = pair.tcp_a().rto_ms() as i64;
    pair.advance_both(rto + 5);
    pair.transfer_one();

    let cap = pair.drain_captured();
    let probes_before = cap.tcp()
        .direction(Dir::AtoB)
        .filter(|f| f.payload_len == 1)
        .count();
    assert_ok!(probes_before >= 1, "first persist probe not sent");

    // Open the window.
    let open = build_tcp_data(
        pair.mac_b, pair.mac_a,
        pair.ip_b,  pair.ip_a,
        80, 12345,
        b_snd_nxt,
        a_snd_una,
        b"",
    );
    pair.inject_to_a(open);
    pair.transfer_one();

    // Verify persist disarmed after window opens.
    let timers = pair.tcp_a().timer_state();
    assert_ok!(timers.persist_ns.is_none(), "persist still armed after window open: {timers:?}");

    pair.clear_capture();

    pair.advance_both(rto * 2 + 15);
    pair.transfer_one();

    let cap2 = pair.drain_captured();
    let probes_after = cap2.tcp()
        .direction(Dir::AtoB)
        .filter(|f| f.payload_len == 1)
        .count();
    assert_ok!(
        probes_after == 0,
        "persist probe fired after window opened ({probes_after} probes)"
    );

    // Data should resume now that the window is open.
    let data_sent = cap2.tcp()
        .direction(Dir::AtoB)
        .with_data()
        .map(|f| f.payload_len)
        .sum::<usize>();
    assert_ok!(
        data_sent > 0,
        "no data sent after window opened — send buffer should have drained"
    );

    Ok(())
}

// ── rto_does_not_fire_during_persist ─────────────────────────────────────────
//
// Implementation choice: RTO is disarmed while persist timer is active.
// RFC 1122 §4.2.2.17 does not explicitly prohibit RTO during persist, but
// persist and retransmission are mutually exclusive timer states.
#[test]
fn rto_does_not_fire_during_persist() -> TestResult {
    use rawket::bridge::LinkProfile;
    let mut pair = setup_tcp_pair()
        .profile(LinkProfile::leased_line_100m())
        .connect();
    setup_zero_window(&mut pair)?;

    pair.add_impairment_to_b(Impairment::Drop(PacketSpec::any()));

    pair.tcp_a_mut().send(b"world")?;

    // Verify RTO is disarmed during persist (persist takes over).
    let timers = pair.tcp_a().timer_state();
    assert_ok!(timers.persist_ns.is_some(), "persist not armed: {timers:?}");

    // Advance well past rto_max_ms.
    let rto_max = pair.tcp_cfg.rto_max_ms as i64;
    for _ in 0..((rto_max * 2 / 500) + 1) {
        pair.advance_both(500);
        pair.transfer_one();
    }

    assert_state(pair.tcp_a(), State::Established, "A should be Established during persist")?;

    let cap = pair.drain_captured();
    // Probes are dropped by our impairment; use all_tcp() to count all A→B frames.
    let oversized = cap.all_tcp()
        .direction(Dir::AtoB)
        .filter(|f| f.payload_len > 1)
        .count();
    assert_ok!(
        oversized == 0,
        "RTO retransmit fired during persist ({oversized} frames with payload > 1)"
    );

    let probe_count = cap.all_tcp()
        .direction(Dir::AtoB)
        .filter(|f| f.payload_len == 1)
        .count();
    assert_ok!(
        probe_count >= 1,
        "no persist probes sent — test scenario may be vacuous"
    );

    Ok(())
}

// ── persist_does_not_timeout_connection ──────────────────────────────────────
//
// RFC 1122 §4.2.2.17: TCP MUST NOT close a connection during persist probing.
#[test]
fn persist_does_not_timeout_connection() -> TestResult {
    use rawket::bridge::LinkProfile;
    let mut pair = setup_tcp_pair()
        .profile(LinkProfile::leased_line_100m())
        .connect();
    setup_zero_window(&mut pair)?;

    pair.add_impairment_to_b(Impairment::Drop(PacketSpec::any()));

    pair.tcp_a_mut().send(b"world")?;

    // Advance 10 seconds with unanswered probes.
    for _ in 0..100 {
        pair.advance_both(100);
        pair.transfer_one();
    }

    assert_state(pair.tcp_a(), State::Established, "persist must not timeout the connection")?;

    let cap = pair.drain_captured();
    let probe_count = cap.all_tcp()
        .direction(Dir::AtoB)
        .filter(|f| f.payload_len == 1)
        .count();
    assert_ok!(
        probe_count >= 3,
        "expected ≥3 unanswered persist probes, got {probe_count}"
    );

    Ok(())
}

// ── persist_probe_seq ─────────────────────────────────────────────────────────
//
// Implementation choice: persist probe uses seq = SND.NXT - 1 (Stevens
// convention).  RFC 9293 §3.8.6.1 requires transmitting "at least one octet
// of new data" but does not specify the sequence number.
#[test]
fn persist_probe_seq() -> TestResult {
    use rawket::bridge::LinkProfile;
    let mut pair = setup_tcp_pair()
        .profile(LinkProfile::leased_line_100m())
        .connect();
    setup_zero_window(&mut pair)?;

    pair.tcp_a_mut().send(b"world")?;
    let snd_nxt = pair.tcp_a().snd_nxt();

    let rto = pair.tcp_a().rto_ms() as i64;
    pair.advance_both(rto + 5);
    pair.transfer_one();

    let cap = pair.drain_captured();
    let probe = cap.tcp()
        .direction(Dir::AtoB)
        .filter(|f| f.payload_len == 1)
        .next()
        .ok_or_else(|| TestFail::new("no persist probe found"))?;

    let expected_seq = snd_nxt.wrapping_sub(1);
    assert_ok!(
        probe.tcp.seq == expected_seq,
        "persist probe seq ({}) != SND.NXT-1 ({expected_seq})",
        probe.tcp.seq
    );

    Ok(())
}
