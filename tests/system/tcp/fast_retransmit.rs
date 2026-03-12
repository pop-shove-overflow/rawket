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
