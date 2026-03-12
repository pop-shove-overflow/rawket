use rawket::{
    bridge::{Impairment, LinkProfile, PacketSpec},
    filter,
    tcp::{TcpFlags, TcpSocket},
};
use crate::{
    assert::{TestFail, assert_dsack, assert_sack_blocks, assert_sack_permitted},
    assert_ok,
    capture::ParsedFrameExt,
    harness::{a_to_b, setup_network_pair, setup_tcp_pair},
    packet::{build_tcp_data, build_tcp_syn},
    TestResult,
};

// RFC 2018 §3: "If sent at all, SACK options SHOULD be included in all ACKs
// which do not ACK the highest sequence number in the data receiver's queue."
// OOO segment with a 1-byte gap: B should SACK the OOO range.
#[test]
fn basic_ooo_one_gap() -> TestResult {
    use rawket::bridge::LinkProfile;
    let mut pair = setup_tcp_pair()
        .profile(LinkProfile::leased_line_100m())
        .connect();

    pair.tcp_a_mut().send(b"a")?;
    pair.transfer();

    let cap = pair.drain_captured();
    let af = cap.tcp().from_a().with_data().next()
        .ok_or_else(|| TestFail::new("no AtoB data"))?;
    let b_rcv_nxt = af.tcp.seq + af.payload_len as u32;
    let b_snd_nxt = af.tcp.ack;

    pair.clear_capture();

    // Inject seg3 (OOO: seq = b_rcv_nxt+1, skips 1 byte).
    let seg3 = a_to_b(&pair, b_rcv_nxt + 1, b_snd_nxt, b"c");
    pair.inject_to_b(seg3);
    pair.transfer_one();

    // B should have sent ACK with SACK block for [b_rcv_nxt+1, b_rcv_nxt+2).
    let cap = pair.drain_captured();
    let ooo_ack = cap.tcp().from_b()
        .with_tcp_flags(TcpFlags::ACK)
        .find(|f| !f.tcp.opts.sack_blocks.is_empty())
        .ok_or_else(|| TestFail::new("B did not send SACK ACK for OOO segment"))?;

    assert_ok!(ooo_ack.tcp.ack == b_rcv_nxt,
        "B's ACK should be {b_rcv_nxt} but got {}", ooo_ack.tcp.ack);
    assert_sack_blocks(&ooo_ack, &[(b_rcv_nxt + 1, b_rcv_nxt + 2)], "OOO SACK block")?;

    pair.clear_capture();

    // Inject seg2 (gap-filling: seq = b_rcv_nxt).
    let seg2 = a_to_b(&pair, b_rcv_nxt, b_snd_nxt, b"b");
    pair.inject_to_b(seg2);
    pair.transfer_one();

    // B's ACK should advance past b_rcv_nxt+2.
    let cap = pair.drain_captured();
    let full_ack = cap.tcp().from_b().with_tcp_flags(TcpFlags::ACK)
        .map(|f| f.tcp.ack).max()
        .ok_or_else(|| TestFail::new("no ACK from B after gap fill"))?;
    assert_ok!(full_ack >= b_rcv_nxt + 2,
        "B's ACK ({full_ack}) did not advance past b_rcv_nxt+2 ({})", b_rcv_nxt + 2);

    Ok(())
}

// RFC 2018 §3: each contiguous OOO region generates a separate SACK block.
// 2 OOO segments with a gap between them — B should SACK both blocks.
#[test]
fn multiple_gaps_two_blocks() -> TestResult {
    use rawket::bridge::LinkProfile;
    let mut pair = setup_tcp_pair()
        .profile(LinkProfile::leased_line_100m())
        .connect();

    pair.tcp_a_mut().send(b"a")?;
    pair.transfer();

    let cap = pair.drain_captured();
    let af = cap.tcp().from_a().with_data().next().ok_or_else(|| TestFail::new("no AtoB data"))?;
    let b_rcv_nxt = af.tcp.seq + af.payload_len as u32;
    let b_snd_nxt = af.tcp.ack;
    pair.clear_capture();

    let seg_b = a_to_b(&pair, b_rcv_nxt + 1, b_snd_nxt, b"b");
    let seg_d = a_to_b(&pair, b_rcv_nxt + 3, b_snd_nxt, b"d");

    pair.inject_to_b(seg_b);
    pair.inject_to_b(seg_d);
    pair.transfer_one();

    let cap = pair.drain_captured();
    let sack_acks: Vec<_> = cap.tcp().from_b()
        .with_tcp_flags(TcpFlags::ACK)
        .filter(|f| !f.tcp.opts.sack_blocks.is_empty())
        .collect();
    assert_ok!(!sack_acks.is_empty(), "B sent no SACK ACKs for two OOO segments");

    let last_sack = sack_acks.last().unwrap();
    let blocks = &last_sack.tcp.opts.sack_blocks;
    assert_ok!(blocks.len() == 2, "expected 2 SACK blocks, got {}: {:?}", blocks.len(), blocks);

    // Exact SACK block boundaries: seg_b = [rcv_nxt+1, rcv_nxt+2), seg_d = [rcv_nxt+3, rcv_nxt+4).
    let has_b = blocks.iter().any(|&(l, r)| l == b_rcv_nxt + 1 && r == b_rcv_nxt + 2);
    let has_d = blocks.iter().any(|&(l, r)| l == b_rcv_nxt + 3 && r == b_rcv_nxt + 4);
    assert_ok!(has_b, "SACK missing exact block for seg_b [{}, {}): {:?}",
        b_rcv_nxt + 1, b_rcv_nxt + 2, blocks);
    assert_ok!(has_d, "SACK missing exact block for seg_d [{}, {}): {:?}",
        b_rcv_nxt + 3, b_rcv_nxt + 4, blocks);

    Ok(())
}
