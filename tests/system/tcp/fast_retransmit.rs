use rawket::bridge::LinkProfile;
use crate::{
    assert::{assert_timestamps_present, TestFail},
    assert_ok,
    capture::ParsedFrameExt,
    harness::{b_to_a, setup_tcp_pair},
    packet::{build_tcp_data_with_sack_ts, recompute_frame_tcp_checksum},
    TestResult,
};

// ── three_dupacks ─────────────────────────────────────────────────────────────
//
// RFC 5681 §3.2: Upon receipt of 3 duplicate ACKs, TCP MUST retransmit the
// segment that appears to be lost (fast retransmit).
//
// Send "hello" from A; then inject 3 duplicate ACKs pointing at snd_una.
// Fast retransmit must fire: the same sequence number appears twice in the
// AtoB capture (original send + retransmit).
#[test]
fn three_dupacks() -> TestResult {
    let mut pair = setup_tcp_pair()
        .profile(LinkProfile::leased_line_100m())
        .connect();

    // Drop B→A so A never gets the real ACK (snd_una stays put).
    pair.blackhole_to_a();

    pair.tcp_a_mut().send(b"hello")?;
    // Just send the data out — don't run to quiescence (RTO would fire).
    pair.transfer_one();

    let cap = pair.drain_captured();
    let data_frame = cap.all_tcp().from_a().with_data().next()
        .ok_or_else(|| TestFail::new("no AtoB data frame after send(hello)"))?;
    let a_snd_una = data_frame.tcp.seq;
    let b_snd_nxt = data_frame.tcp.ack;

    // Clear blackhole so injected DupACKs reach A.
    pair.clear_impairments();

    for _ in 0..3u32 {
        let frame = b_to_a(&pair, b_snd_nxt, a_snd_una, b"");
        pair.inject_to_a(frame);
    }
    pair.transfer_one();

    // The first drain_captured() above consumed the original "hello" send.
    // This capture should contain exactly the fast-retransmit (1 frame).
    let cap = pair.drain_captured();
    let retx_frames: Vec<_> = cap.all_tcp().from_a().with_data()
        .filter(|f| f.tcp.seq == a_snd_una)
        .collect();
    assert_ok!(
        retx_frames.len() == 1,
        "expected 1 fast-retransmit frame with seq={a_snd_una}, got {}",
        retx_frames.len()
    );

    // RFC 7323 §3.2: fast retransmit must carry timestamps.
    assert_timestamps_present(&retx_frames[retx_frames.len() - 1], "fast retransmit")?;

    // BBR must have registered the loss: bytes_in_flight should still reflect
    // the unacked segment (it hasn't been ACKed yet, only retransmitted).
    let bif = pair.tcp_a().bytes_in_flight();
    assert_ok!(bif > 0, "bytes_in_flight is 0 after fast retransmit — loss not tracked");

    Ok(())
}


// ── partial_ack ───────────────────────────────────────────────────────────────
//
// Partial ACK handling: a partial ACK (acks some but not all outstanding data)
// must advance snd_una without disrupting the connection.  RFC 6582 §3.2
// (NewReno) and RFC 6675 §5 (SACK) both describe partial ACK handling; our
// SACK+BBR stack follows neither exactly.  The assertion (bif == 3 after
// acking 2 of 5 bytes) is implementation-specific.
#[test]
fn partial_ack() -> TestResult {
    let mut pair = setup_tcp_pair()
        .profile(LinkProfile::leased_line_100m())
        .connect();

    pair.blackhole_to_a();
    pair.tcp_a_mut().send(b"hello")?;
    pair.transfer_one();

    let cap = pair.drain_captured();
    let data_frame = cap.all_tcp().from_a().with_data().next()
        .ok_or_else(|| TestFail::new("no AtoB data frame"))?;
    let a_snd_una = data_frame.tcp.seq;
    let b_snd_nxt = data_frame.tcp.ack;

    let snd_una_before = pair.tcp_a().snd_una();
    pair.clear_impairments();

    // 3 DUPACKs → fast retransmit.
    for _ in 0..3u32 {
        let frame = b_to_a(&pair, b_snd_nxt, a_snd_una, b"");
        pair.inject_to_a(frame);
    }
    pair.transfer_one();

    // Inject partial ACK: acks first 2 of the 5 bytes.
    let frame = b_to_a(&pair, b_snd_nxt, a_snd_una + 2, b"");
    pair.inject_to_a(frame);
    pair.transfer_one();

    // snd_una must advance by exactly 2 (partial ACK).
    let snd_una_after = pair.tcp_a().snd_una();
    assert_ok!(
        snd_una_after == snd_una_before.wrapping_add(2),
        "snd_una did not advance by 2: before={snd_una_before}, after={snd_una_after}"
    );

    // Connection must survive (Established).
    assert_ok!(
        pair.tcp_a().state == rawket::tcp::State::Established,
        "A not Established after partial ACK: {:?}", pair.tcp_a().state
    );

    // bytes_in_flight must reflect the partial ACK: 3 bytes still unacked.
    let bif = pair.tcp_a().bytes_in_flight();
    assert_ok!(
        bif == 3,
        "bytes_in_flight after partial ACK should be 3 (5 sent - 2 acked), got {bif}"
    );

    Ok(())
}

// ── dupack_count_resets ───────────────────────────────────────────────────────
//
// RFC 6675 §5: "If the incoming ACK is a cumulative acknowledgment, the
// TCP MUST reset DupAcks to zero."
//
// Inject 2 DUPACKs (not enough for fast retransmit), then a full ACK that
// advances snd_una; inject another 2 DUPACKs for a new segment — still no
// retransmit (counter was reset).  A third DUPACK triggers fast retransmit.
#[test]
fn dupack_count_resets() -> TestResult {
    let mut pair = setup_tcp_pair()
        .profile(LinkProfile::leased_line_100m())
        .connect();

    // Phase 1: send "hello", blackhole to prevent real ACK.
    pair.blackhole_to_a();
    pair.tcp_a_mut().send(b"hello")?;
    pair.transfer_one();

    let cap = pair.drain_captured();
    let data_frame = cap.all_tcp().from_a().with_data().next()
        .ok_or_else(|| TestFail::new("no AtoB data frame"))?;
    let a_snd_una = data_frame.tcp.seq;
    let b_snd_nxt = data_frame.tcp.ack;
    pair.clear_impairments();

    // 2 DUPACKs — must NOT trigger fast retransmit.
    for _ in 0..2u32 {
        let frame = b_to_a(&pair, b_snd_nxt, a_snd_una, b"");
        pair.inject_to_a(frame);
    }
    pair.transfer_one();

    let cap = pair.drain_captured();
    let retx_after_2dup = cap.all_tcp().from_a().with_data()
        .filter(|f| f.tcp.seq == a_snd_una)
        .count();
    assert_ok!(retx_after_2dup == 0, "fast retransmit fired prematurely after 2 DUPACKs");

    // Full ACK clears "hello" → dupack_count resets.
    let frame = b_to_a(&pair, b_snd_nxt, a_snd_una + 5, b"");
    pair.inject_to_a(frame);
    pair.transfer_one();
    pair.clear_capture();

    pair.advance_both(1000);

    // Phase 2: send "world", blackhole again.
    pair.blackhole_to_a();
    pair.tcp_a_mut().send(b"world")?;
    pair.transfer_one();

    let cap = pair.drain_captured();
    let world_frame = cap.all_tcp().from_a().with_data().next()
        .ok_or_else(|| TestFail::new("no AtoB data frame for 'world'"))?;
    let a_snd_una2 = world_frame.tcp.seq;
    pair.clear_impairments();

    // 2 DUPACKs (counter reset — no retransmit).
    for _ in 0..2u32 {
        let frame = b_to_a(&pair, b_snd_nxt, a_snd_una2, b"");
        pair.inject_to_a(frame);
    }
    pair.transfer_one();

    let cap = pair.drain_captured();
    let retx_after_reset_2dup = cap.all_tcp().from_a().with_data()
        .filter(|f| f.tcp.seq == a_snd_una2)
        .count();
    assert_ok!(
        retx_after_reset_2dup == 0,
        "fast retransmit fired after only 2 DUPACKs following reset (count not reset?)"
    );

    // 3rd DUPACK — fast retransmit fires.
    let frame = b_to_a(&pair, b_snd_nxt, a_snd_una2, b"");
    pair.inject_to_a(frame);
    pair.transfer_one();

    let cap = pair.drain_captured();
    let retx_after_3rd_dup = cap.all_tcp().from_a().with_data()
        .filter(|f| f.tcp.seq == a_snd_una2)
        .count();
    assert_ok!(
        retx_after_3rd_dup >= 1,
        "fast retransmit did not fire after 3 DUPACKs (count was reset correctly but did not fire)"
    );

    Ok(())
}

// ── window_update_not_dupack ────────────────────────────────────────────────
//
// RFC 5681 §3.2: Window-update ACKs (same ack#, different window) SHOULD NOT
// count as duplicate ACKs.  Verify that 3 injected window-update ACKs do NOT
// trigger fast retransmit.
#[test]
fn window_update_not_dupack() -> TestResult {
    let mut pair = setup_tcp_pair()
        .profile(LinkProfile::leased_line_100m())
        .connect();

    pair.blackhole_to_a();
    pair.tcp_a_mut().send(b"hello")?;
    pair.transfer_one();

    let cap = pair.drain_captured();
    let data_frame = cap.all_tcp().from_a().with_data().next()
        .ok_or_else(|| TestFail::new("no AtoB data frame"))?;
    let a_snd_una = data_frame.tcp.seq;
    let b_snd_nxt = data_frame.tcp.ack;
    pair.clear_impairments();

    // Inject 3 window-update ACKs: same ack number, different windows.
    for win in [32000u16, 48000, 64000] {
        let mut wup = b_to_a(&pair, b_snd_nxt, a_snd_una, b"");
        wup[48..50].copy_from_slice(&win.to_be_bytes());
        recompute_frame_tcp_checksum(&mut wup);
        pair.inject_to_a(wup);
    }
    pair.transfer_one();

    // Count AtoB data frames with a_snd_una: must be 0 (no retransmit).
    // Window-update ACKs (same ack#, different window) are not duplicate ACKs
    // per RFC 5681 §3.2 and must not trigger fast retransmit.
    let cap = pair.drain_captured();
    let retx_count = cap.all_tcp().from_a().with_data()
        .filter(|f| f.tcp.seq == a_snd_una)
        .count();
    assert_ok!(
        retx_count == 0,
        "expected 0 data frames (no fast-retransmit from window-update ACKs), got {retx_count}"
    );

    // Connection must survive regardless.
    assert_ok!(
        pair.tcp_a().state == rawket::tcp::State::Established,
        "A not Established after window-update ACKs: {:?}", pair.tcp_a().state
    );

    Ok(())
}

// ── triggers_bbr_loss ───────────────────────────────────────────────────────
//
// draft-ietf-ccwg-bbr-04 §5.5: loss triggers BBRAdaptLowerBounds with
// Beta=0.7.  RFC 5681 §3.2 mandates ssthresh = FlightSize/2, but BBR
// uses its own cwnd reduction algorithm.  This test validates BBR behavior.
//
// Phase 1: grow cwnd with a lossless transfer.
// Phase 2: drop one segment via bridge impairment → B generates DUPACKs →
//          fast retransmit fires → BBR reduces cwnd via Beta=0.7 (§5.5).
#[test]
fn triggers_bbr_loss() -> TestResult {
    let mut pair = setup_tcp_pair()
        .profile(LinkProfile::leased_line_100m())
        .connect();

    // Phase 1: lossless incremental transfers to drive BBR past Startup
    // into ProbeBW, where cwnd growth is BDP-bounded (not additive).
    for _ in 0..20 {
        pair.tcp_a_mut().send(&vec![0xAAu8; 50_000])?;
        pair.transfer();
        if pair.tcp_a().bbr_filled_pipe() {
            break;
        }
    }

    let cwnd_before = pair.tcp_a().bbr_cwnd();
    let mss = pair.tcp_a().peer_mss() as u32;
    assert_ok!(
        cwnd_before > 4 * mss,
        "cwnd ({cwnd_before}) at floor after warmup — cannot verify reduction"
    );

    // Phase 2: drop the first data segment → B receives subsequent
    // segments out-of-order → B generates DUPACKs → fast retransmit.
    pair.clear_capture();
    pair.drop_next_data_to_b();
    pair.tcp_a_mut().send(&vec![0xBBu8; 10_000])?;
    pair.transfer();

    // Verify the dropped segment was actually retransmitted (not just cwnd
    // reduction from RTO or other path).
    let cap = pair.drain_captured();
    let dropped = cap.all_tcp().from_a().dropped().with_data().next()
        .ok_or_else(|| TestFail::new("no dropped segment — impairment didn't fire"))?;
    let retx_count = cap.all_tcp().from_a().delivered().with_data()
        .filter(|f| f.tcp.seq == dropped.tcp.seq)
        .count();
    assert_ok!(
        retx_count >= 1,
        "dropped segment seq={} was never retransmitted", dropped.tcp.seq
    );

    // BBR §5.5: on first loss, BBRInitLowerBounds snapshots cwnd into
    // inflight_shortterm, then BBRLossLowerBounds applies Beta=0.7.
    // BBRBoundCwndForModel caps cwnd to inflight_shortterm.
    let cwnd_after = pair.tcp_a().bbr_cwnd();
    assert_ok!(
        cwnd_after < cwnd_before,
        "cwnd must strictly decrease after loss: before={cwnd_before}, after={cwnd_after}"
    );
    // Beta=0.7 → expect ~68-70% of pre-loss cwnd.  Allow 65-75% for
    // BBRModulateCwndForRecovery's newly_lost subtraction on top.
    let lo = cwnd_before * 65 / 100;
    let hi = cwnd_before * 75 / 100;
    assert_ok!(
        cwnd_after >= lo && cwnd_after <= hi,
        "cwnd after loss not in Beta=0.7 range: before={cwnd_before}, after={cwnd_after}, \
         expected {lo}..{hi} (65-75%)"
    );

    assert_ok!(
        pair.tcp_a().state == rawket::tcp::State::Established,
        "A not Established after recovery: {:?}", pair.tcp_a().state
    );

    Ok(())
}

// ── fast_retransmit_with_sack ───────────────────────────────────────────
//
// RFC 6675 §4: A SACK-based sender uses SACK information to determine which
// segments are lost; retransmission targets the first un-SACKed hole.
//
// 3 DUPACKs with SACK blocks indicating a later segment was received.
// Fast retransmit should fire for the hole (not the SACKed segment).
// NOTE: The SACK range [+5, +10) covers a sub-range of a single 10-byte
// segment, which is unrealistic (real SACK blocks align to segment
// boundaries).  This is acceptable as a synthetic test: the key behavior
// (retransmit the hole, not the SACKed range) is valid regardless.
#[test]
fn fast_retransmit_with_sack() -> TestResult {
    let mut pair = setup_tcp_pair()
        .profile(LinkProfile::leased_line_100m())
        .connect();

    pair.blackhole_to_a();
    pair.tcp_a_mut().send(b"AAAAAAAAAA")?;
    pair.transfer_one();

    let cap = pair.drain_captured();
    let data_frame = cap.all_tcp().from_a().with_data().next()
        .ok_or_else(|| TestFail::new("no AtoB data"))?;
    let a_snd_una = data_frame.tcp.seq;
    let b_snd_nxt = data_frame.tcp.ack;
    pair.clear_impairments();
    let a_ts = data_frame.tcp.opts.timestamps.map(|(v, _)| v).unwrap_or(1);
    let b_ts = pair.clock_b.monotonic_ms() as u32;
    let (mac_b, mac_a, ip_b, ip_a) = (pair.mac_b, pair.mac_a, pair.ip_b, pair.ip_a);

    // Inject 3 DUPACKs with SACK blocks: ack=a_snd_una (hole at [0,5)),
    // SACK=[a_snd_una+5, a_snd_una+10) (second segment received).
    for i in 0..3u32 {
        let dup = build_tcp_data_with_sack_ts(
            mac_b, mac_a, ip_b, ip_a,
            80, 12345,
            b_snd_nxt, a_snd_una, // DUPACK: same ack (hole at a_snd_una)
            b_ts + 1 + i, a_ts,
            &[(a_snd_una + 5, a_snd_una + 10)],
            b"",
        );
        pair.inject_to_a(dup);
    }
    pair.transfer_one();

    // Fast retransmit must fire: retransmit at a_snd_una (the hole).
    let cap = pair.drain_captured();
    let retx_at_hole = cap.all_tcp().from_a().with_data()
        .filter(|f| f.tcp.seq == a_snd_una)
        .count();
    assert_ok!(
        retx_at_hole >= 1,
        "expected ≥1 retransmit at seq={a_snd_una} (the hole), got {retx_at_hole}"
    );

    // The SACKed range [+5, +10) should NOT be retransmitted.
    let retx_at_sacked = cap.all_tcp().from_a().with_data()
        .filter(|f| f.tcp.seq == a_snd_una + 5)
        .count();
    assert_ok!(
        retx_at_sacked == 0,
        "SACKed range retransmitted ({retx_at_sacked} frames at seq={})", a_snd_una + 5
    );

    Ok(())
}

// ── dupack_during_zero_window ───────────────────────────────────────────
//
// RFC 5681 §2: a duplicate ACK requires "outstanding data" (condition a:
// snd_una != snd_nxt).  When the peer advertises zero window, new data
// queued via send() cannot be transmitted (peer window gate in
// flush_send_buf), so snd_nxt == snd_una — there is no outstanding data.
// DUPACKs in this state fail condition (a) and do not trigger fast
// retransmit.
#[test]
fn dupack_during_zero_window() -> TestResult {
    let mut pair = setup_tcp_pair()
        .profile(LinkProfile::leased_line_100m())
        .connect();

    pair.tcp_a_mut().send(b"x")?;
    pair.transfer();

    let cap = pair.drain_captured();
    let data_frame = cap.tcp().from_a().with_data().next()
        .ok_or_else(|| TestFail::new("no AtoB data"))?;
    let a_snd_una = data_frame.tcp.seq + 1;
    let b_snd_nxt = data_frame.tcp.ack;

    // Inject zero-window ACK.
    let mut zw = b_to_a(&pair, b_snd_nxt, a_snd_una, b"");
    zw[48] = 0; zw[49] = 0;
    recompute_frame_tcp_checksum(&mut zw);
    pair.inject_to_a(zw);
    pair.transfer_one();

    // Verify A processed the zero-window ACK.
    assert_ok!(
        pair.tcp_a().snd_wnd() == 0,
        "snd_wnd should be 0 after zero-window ACK, got {}", pair.tcp_a().snd_wnd()
    );

    pair.advance_both(1000);
    pair.tcp_a_mut().send(b"world")?;

    pair.clear_capture();

    // Inject 3 DUPACKs with zero window.
    for _ in 0..3u32 {
        let mut dup = b_to_a(&pair, b_snd_nxt, a_snd_una, b"");
        dup[48] = 0; dup[49] = 0;
        recompute_frame_tcp_checksum(&mut dup);
        pair.inject_to_a(dup);
    }
    pair.transfer_one();

    // No outstanding data (snd_nxt == snd_una), so DUPACKs fail RFC 5681
    // condition (a) and fast retransmit does not fire.
    let cap = pair.drain_captured();
    let data_retx = cap.all_tcp().from_a()
        .filter(|f| f.payload_len > 0)
        .count();
    assert_ok!(
        data_retx == 0,
        "data sent during zero window ({data_retx} segments) — no outstanding data, so no retransmit"
    );

    assert_ok!(
        pair.tcp_a().state == rawket::tcp::State::Established,
        "A not Established: {:?}", pair.tcp_a().state
    );

    Ok(())
}
