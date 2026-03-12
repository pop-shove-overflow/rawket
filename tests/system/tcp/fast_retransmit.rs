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
