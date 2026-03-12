use rawket::{
    bridge::{Impairment, LinkProfile, PacketSpec},
    filter,
    tcp::{TcpConfig, TcpFlags, TcpSocket},
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

// RFC 2018 §2: SACK-Permitted is negotiated during the three-way handshake.
// SYN and SYN-ACK must carry SACK-Permitted option.
#[test]
fn sack_permitted_negotiation() -> TestResult {
    use rawket::bridge::LinkProfile;
    let (_pair, cap) = setup_tcp_pair()
        .profile(LinkProfile::leased_line_100m())
        .connect_and_capture();

    let syn = cap.tcp().from_a()
        .with_tcp_flags(TcpFlags::SYN)
        .without_tcp_flags(TcpFlags::ACK)
        .next()
        .ok_or_else(|| TestFail::new("no SYN from A"))?;

    let syn_ack = cap.tcp().from_b()
        .with_tcp_flags(TcpFlags::SYN)
        .with_tcp_flags(TcpFlags::ACK)
        .next()
        .ok_or_else(|| TestFail::new("no SYN-ACK from B"))?;

    assert_sack_permitted(&syn,     "SYN SACK-Permitted")?;
    assert_sack_permitted(&syn_ack, "SYN-ACK SACK-Permitted")?;

    Ok(())
}

// Implementation limit: OOO buffer holds at most rx_ooo_max (default 8)
// segments.  RFC 2018 §8 permits discarding previously SACKed data, but
// does not mandate a specific buffer size.
#[test]
fn ooo_buffer_limit() -> TestResult {
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

    // Implementation limit: rx_ooo buffer holds at most 8 segments.
    // This is a fixed internal constant (not configurable).  If the eviction
    // policy changes (e.g., to LRU or merge-based), this assertion should be
    // updated to match the new capacity semantic.
    let rx_ooo_max = 8usize;

    for i in 0..=(rx_ooo_max as u32) {
        let offset = i * 2 + 1;
        let seg = a_to_b(&pair, b_rcv_nxt + offset, b_snd_nxt, b"x");
        pair.inject_to_b(seg);
        pair.transfer_one();
    }

    let cap = pair.drain_captured();
    let sack_seqs: std::collections::BTreeSet<u32> = cap.tcp().from_b()
        .flat_map(|f| f.tcp.opts.sack_blocks.iter().map(|&(l, _)| l).collect::<Vec<_>>())
        .collect();

    assert_ok!(
        sack_seqs.len() == rx_ooo_max,
        "expected exactly {rx_ooo_max} unique SACK block starts, got {}: {:?}",
        sack_seqs.len(), sack_seqs
    );

    // 9th segment (offset 17) must have been dropped — not present in any SACK.
    let ninth_offset = b_rcv_nxt + (rx_ooo_max as u32) * 2 + 1;
    assert_ok!(
        !sack_seqs.contains(&ninth_offset),
        "9th OOO segment (offset {ninth_offset}) should be dropped but appears in SACK"
    );

    Ok(())
}

// RFC 2018 §2: "This option may be sent in a SYN by a TCP that has been
// extended to receive (and presumably process) the SACK option once the
// connection has opened." If peer SYN lacks SACK-Permitted, server must NOT
// send SACK blocks.
#[test]
fn sack_not_sent_without_permitted() -> TestResult {
    use rawket::bridge::LinkProfile;
    let mut np = setup_network_pair()
        .profile(LinkProfile::leased_line_100m());
    let cfg = TcpConfig::default();

    let server = TcpSocket::accept(
        np.iface_b(),
        "10.0.0.2:80".parse().unwrap(),
        |_| {}, |_| {},
        cfg,
    )?;
    np.add_tcp_b(server);

    let isn_a = 0x4000_0000u32;
    let syn = build_tcp_syn(
        np.mac_a, np.mac_b,
        np.ip_a,  np.ip_b,
        12345, 80,
        isn_a, 0,
        0x02,
        Some(1460), None, None, false, // no SACK-Permitted
    );
    np.inject_to_b(syn);
    np.transfer_one();

    let cap = np.drain_captured();
    let syn_ack = cap.tcp().from_b()
        .with_tcp_flags(TcpFlags::SYN)
        .with_tcp_flags(TcpFlags::ACK)
        .next()
        .ok_or_else(|| TestFail::new("no SYN-ACK from B"))?;

    assert_ok!(
        !syn_ack.tcp.opts.sack_permitted,
        "SYN-ACK has SACK-Permitted despite peer SYN omitting it"
    );

    let ack = build_tcp_data(
        np.mac_a, np.mac_b,
        np.ip_a,  np.ip_b,
        12345, 80,
        isn_a + 1, syn_ack.tcp.seq + 1,
        &[],
    );
    np.inject_to_b(ack);
    np.transfer_one();

    let b_rcv_nxt = isn_a + 1;
    let b_snd_nxt = syn_ack.tcp.seq + 1;
    np.clear_capture();

    // Inject OOO segment.
    let ooo = build_tcp_data(
        np.mac_a, np.mac_b,
        np.ip_a,  np.ip_b,
        12345, 80,
        b_rcv_nxt + 1, b_snd_nxt,
        b"ooo",
    );
    np.inject_to_b(ooo);
    np.transfer_one();

    let cap = np.drain_captured();
    let has_sack = cap.tcp().from_b()
        .with_tcp_flags(TcpFlags::ACK)
        .any(|f| !f.tcp.opts.sack_blocks.is_empty());
    assert_ok!(!has_sack, "B sent SACK blocks despite peer not sending SACK-Permitted");

    Ok(())
}

// RFC 2018 §4: most recently received OOO segment's SACK block must be first.
#[test]
fn most_recent_block_first() -> TestResult {
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

    // Inject first OOO at +1.
    let seg1 = a_to_b(&pair, b_rcv_nxt + 1, b_snd_nxt, b"a");
    pair.inject_to_b(seg1);
    pair.transfer_one();

    let cap = pair.drain_captured();
    let first_sack = cap.tcp().from_b()
        .filter(|f| !f.tcp.opts.sack_blocks.is_empty())
        .last()
        .ok_or_else(|| TestFail::new("no SACK ACK from B after first OOO segment"))?;
    let has_seg1 = first_sack.tcp.opts.sack_blocks.iter()
        .any(|&(l, r)| l == b_rcv_nxt + 1 && r == b_rcv_nxt + 2);
    assert_ok!(has_seg1, "first SACK missing exact block for seg1: {:?}", first_sack.tcp.opts.sack_blocks);

    pair.clear_capture();

    // Inject second OOO at +3 (most recent).
    let seg2 = a_to_b(&pair, b_rcv_nxt + 3, b_snd_nxt, b"b");
    pair.inject_to_b(seg2);
    pair.transfer_one();

    let cap = pair.drain_captured();
    let sack_ack = cap.tcp().from_b()
        .filter(|f| !f.tcp.opts.sack_blocks.is_empty())
        .last()
        .ok_or_else(|| TestFail::new("no SACK ACK from B after second OOO segment"))?;
    let blocks = &sack_ack.tcp.opts.sack_blocks;
    assert_ok!(blocks.len() == 2, "expected 2 SACK blocks, got {}: {:?}", blocks.len(), blocks);

    let has_seg1 = blocks.iter().any(|&(l, r)| l == b_rcv_nxt + 1 && r == b_rcv_nxt + 2);
    let has_seg2 = blocks.iter().any(|&(l, r)| l == b_rcv_nxt + 3 && r == b_rcv_nxt + 4);
    assert_ok!(has_seg1, "SACK missing exact block for seg1: {:?}", blocks);
    assert_ok!(has_seg2, "SACK missing exact block for seg2: {:?}", blocks);

    // RFC 2018 §4: most recently received block must be first.
    assert_ok!(
        blocks[0] == (b_rcv_nxt + 3, b_rcv_nxt + 4),
        "first SACK block {:?} is not seg2 [{}, {}) — most recent must be first",
        blocks[0], b_rcv_nxt + 3, b_rcv_nxt + 4
    );

    Ok(())
}

// RFC 6675 §4: SACK-based loss recovery retransmits only segments in "holes"
// (gaps between SACK blocks). SACKed segments must NOT be retransmitted.
#[test]
fn sender_skips_sacked_on_retransmit() -> TestResult {
    use rawket::bridge::LinkProfile;
    let mut pair = setup_tcp_pair()
        .profile(LinkProfile::leased_line_100m())
        .connect();

    // Send initial data to seed BBR estimate.
    pair.tcp_a_mut().send(b"init-data-xxxx")?;
    pair.transfer();
    pair.clear_capture();

    // Drop the 1st data segment from A, then send two batches.
    // B will SACK the gap; A retransmits the hole.
    pair.add_impairment_to_b(Impairment::Drop(PacketSpec::nth_matching(1, filter::tcp::has_data())));
    pair.tcp_a_mut().send(&[0xaau8; 100])?;
    pair.tcp_a_mut().send(&[0xbbu8; 100])?;

    // Clear impairment before transfer so the retransmit can reach B.
    pair.clear_impairments();
    pair.transfer();

    assert_ok!(
        pair.tcp_a().state == rawket::tcp::State::Established,
        "A not Established after SACK retransmit: {:?}", pair.tcp_a().state
    );

    // Verify a dropped segment exists and was retransmitted.
    let cap = pair.drain_captured();
    let seg1_seq = cap.all_tcp()
        .from_a()
        .dropped()
        .with_data()
        .next()
        .map(|f| f.tcp.seq);

    let seq1 = seg1_seq.ok_or_else(|| TestFail::new("no dropped segment — impairment didn't fire"))?;

    let retx_count = cap.all_tcp().from_a().delivered().with_data()
        .filter(|f| f.tcp.seq == seq1)
        .count();
    assert_ok!(retx_count >= 1, "dropped segment (seq={seq1}) was not retransmitted");

    // The key assertion: the retransmit of the hole must happen BEFORE any
    // SACKed segment is re-sent.  Find the timestamp of the first retransmit
    // of the hole, then verify no non-hole segment was sent between the
    // SACK feedback and the hole retransmit.
    let hole_retx_ts = cap.all_tcp().from_a().delivered().with_data()
        .filter(|f| f.tcp.seq == seq1)
        .map(|f| f.ts_ns)
        .min();
    assert_ok!(hole_retx_ts.is_some(), "hole retransmit timestamp missing despite retx_count >= 1");
    let retx_ts = hole_retx_ts.unwrap();
    // Any data frame sent at or after the hole retransmit with a different
    // seq that is LESS than the hole seq must be a needless retransmit of
    // a SACKed segment (sent before the hole in the original flight).
    let bad_retx = cap.all_tcp().from_a().delivered().with_data()
        .filter(|f| f.ts_ns >= retx_ts && f.tcp.seq != seq1
            && (f.tcp.seq.wrapping_sub(seq1) as i32) < 0)
        .count();
    assert_ok!(
        bad_retx == 0,
        "sender retransmitted {bad_retx} SACKed segment(s) (seq < hole) \
         after SACK recovery — must skip SACKed segments"
    );
    // Also verify seg2 (the SACKed segment after the hole) was not re-sent
    // after the hole retransmit.
    let seg2_seq = seq1.wrapping_add(100);
    let seg2_retx = cap.all_tcp().from_a().delivered().with_data()
        .filter(|f| f.tcp.seq == seg2_seq && f.ts_ns >= retx_ts)
        .count();
    assert_ok!(
        seg2_retx == 0,
        "sender retransmitted SACKed seg2 (seq={seg2_seq}) {seg2_retx} time(s) after hole recovery"
    );

    Ok(())
}
