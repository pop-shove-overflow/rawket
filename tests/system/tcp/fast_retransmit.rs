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
// After fast retransmit fires, a partial ACK (acks only part of the segment)
// must advance snd_una but leave the connection Established.
