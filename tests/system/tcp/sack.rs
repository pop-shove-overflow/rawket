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

// RFC 2018 §3: up to 4 SACK blocks may be sent, but timestamps reduce the
// available option space to 3. 4 OOO segments; with TS, at most 3 SACK blocks fit.
#[test]
fn four_block_maximum() -> TestResult {
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

    for &i in [1u32, 3, 5, 7].iter() {
        let seg = a_to_b(&pair, b_rcv_nxt + i, b_snd_nxt, b"x");
        pair.inject_to_b(seg);
        pair.transfer_one();
    }

    let cap = pair.drain_captured();
    let max_blocks = cap.tcp().from_b().with_tcp_flags(TcpFlags::ACK)
        .map(|f| f.tcp.opts.sack_blocks.len())
        .max()
        .unwrap_or(0);

    // TCP options space = 40 bytes.  With timestamps (10 bytes + 2 NOP pad = 12)
    // and SACK-Permitted already negotiated, each SACK block takes 8 bytes.
    // Available: 40 - 12 (TS) - 2 (SACK option kind+len) = 26 bytes → 3 blocks.
    // RFC 2018 allows max 4, but timestamps reduce that to 3.
    assert_ok!(
        max_blocks == 3,
        "expected exactly 3 SACK blocks (TS limits option space to 3), got {max_blocks}"
    );

    // Most recent (offset 7) must be first per RFC 2018 §4.
    let last_sack = cap.tcp().from_b()
        .filter(|f| f.tcp.opts.sack_blocks.len() == 3)
        .last()
        .ok_or_else(|| TestFail::new("no ACK with 3 SACK blocks"))?;
    let blocks = &last_sack.tcp.opts.sack_blocks;
    assert_ok!(
        blocks[0] == (b_rcv_nxt + 7, b_rcv_nxt + 8),
        "first block {:?} should be most recent [{}, {})",
        blocks[0], b_rcv_nxt + 7, b_rcv_nxt + 8
    );

    // All 3 blocks must have exact 1-byte boundaries from the OOO segments.
    for &(l, r) in blocks {
        assert_ok!(
            r == l + 1 && [1, 3, 5, 7].contains(&(l.wrapping_sub(b_rcv_nxt))),
            "unexpected SACK block [{l}, {r}): expected 1-byte block at offset 1, 3, 5, or 7"
        );
    }

    let ts_on_sack = cap.tcp().from_b()
        .filter(|f| !f.tcp.opts.sack_blocks.is_empty())
        .all(|f| f.tcp.opts.timestamps.is_some());
    assert_ok!(ts_on_sack, "SACK ACKs should include TS option");

    Ok(())
}

// RFC 2883 §3: D-SACK — the first SACK block covers data below the cumulative
// ACK, signalling a spurious retransmit. Inject duplicate data already ACKed —
// B must respond with D-SACK.
#[test]
fn dsack_spurious_retransmit() -> TestResult {
    use rawket::bridge::LinkProfile;
    let mut pair = setup_tcp_pair()
        .profile(LinkProfile::leased_line_100m())
        .connect();

    pair.tcp_a_mut().send(b"hello")?;
    pair.transfer();

    let cap = pair.drain_captured();
    let data_frame = cap.tcp().from_a().with_data().next()
        .ok_or_else(|| TestFail::new("no AtoB data frame"))?;
    let a_seq = data_frame.tcp.seq;
    let b_snd_nxt = data_frame.tcp.ack;
    pair.clear_capture();

    let dup = a_to_b(&pair, a_seq, b_snd_nxt, b"hello");
    pair.inject_to_b(dup);
    pair.transfer_one();

    let cap = pair.drain_captured();
    let b_ack = cap.tcp().from_b()
        .with_tcp_flags(TcpFlags::ACK)
        .find(|f| !f.tcp.opts.sack_blocks.is_empty())
        .ok_or_else(|| TestFail::new("B did not send SACK ACK for duplicate segment"))?;

    assert_dsack(&b_ack, "B's D-SACK for spurious retransmit")?;

    // D-SACK block must exactly match the duplicated range [a_seq, a_seq+5).
    let (dl, dr) = b_ack.tcp.opts.sack_blocks[0];
    assert_ok!(
        dl == a_seq && dr == a_seq + 5,
        "D-SACK block [{dl}, {dr}) != expected [{}, {}) for 5-byte duplicate",
        a_seq, a_seq + 5
    );

    Ok(())
}
