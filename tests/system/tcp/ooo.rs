use rawket::tcp::{State, TcpFlags};
use crate::{
    assert::TestFail,
    assert_ok,
    capture::{Dir, ParsedFrameExt},
    harness::{a_to_b, setup_tcp_pair},
    packet::build_tcp_data_with_flags,
    TestResult,
};

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Send 1 byte from A→B, let both sides process it.
/// Returns `(b_rcv_nxt, b_snd_nxt)` and clears the capture.
fn baseline_seqs(pair: &mut crate::harness::TcpSocketPair) -> Result<(u32, u32), TestFail> {
    pair.tcp_a_mut().send(b"a")?;
    pair.transfer();

    let cap = pair.drain_captured();
    let (a_seq, b_ack_field) = {
        let f = cap.tcp()
            .direction(Dir::AtoB)
            .with_data()
            .next()
            .ok_or_else(|| TestFail::new("no AtoB data frame in baseline_seqs"))?;
        (f.tcp.seq, f.tcp.ack)
    };

    Ok((a_seq + 1, b_ack_field))
}

// ── single_ooo_segment ───────────────────────────────────────────────────────
//
// RFC 2018 §3: SACK option generation on out-of-order segment receipt.
// RFC 9293 §3.10.7.4: cumulative ACK advances when gap is filled.
//
// Inject 1 OOO segment then the gap filler; verify SACK ACK + cumulative
// ACK advance.
#[test]
fn single_ooo_segment() -> TestResult {
    use rawket::bridge::LinkProfile;
    let mut pair = setup_tcp_pair()
        .profile(LinkProfile::leased_line_100m())
        .connect();
    let (b_rcv_nxt, b_snd_nxt) = baseline_seqs(&mut pair)?;

    let ooo = a_to_b(&pair, b_rcv_nxt + 1, b_snd_nxt, b"B");
    pair.inject_to_b(ooo);
    pair.transfer_one();

    // B's ACK should remain at b_rcv_nxt with a SACK block.
    let cap = pair.drain_captured();
    let sack_ack = cap.tcp()
        .direction(Dir::BtoA)
        .with_tcp_flags(TcpFlags::ACK)
        .find(|f| !f.tcp.opts.sack_blocks.is_empty());
    assert_ok!(sack_ack.is_some(), "B did not send SACK ACK for OOO segment");

    let ack = sack_ack.unwrap();
    assert_ok!(
        ack.tcp.ack == b_rcv_nxt,
        "B's cumulative ACK should be {b_rcv_nxt} but got {}", ack.tcp.ack
    );

    // Inject gap-filling segment and run to completion.
    let gap_fill = a_to_b(&pair, b_rcv_nxt, b_snd_nxt, b"A");
    pair.inject_to_b(gap_fill);
    let result = pair.transfer();

    let cap2 = pair.drain_captured();
    let max_ack = cap2.tcp()
        .direction(Dir::BtoA)
        .with_tcp_flags(TcpFlags::ACK)
        .map(|f| f.tcp.ack)
        .max();
    let max_ack = max_ack.ok_or_else(|| TestFail::new("no ACK from B after gap fill"))?;
    assert_ok!(
        max_ack == b_rcv_nxt + 2,
        "B's ACK ({max_ack}) should be exactly {} after gap fill", b_rcv_nxt + 2
    );

    // Verify delivered payload: "A" (gap fill) + "B" (OOO) = "AB".
    // (baseline "a" was consumed by drain_b in baseline_seqs.)
    let received = result.b.get(&0).map(|v| v.as_slice()).unwrap_or(&[]);
    assert_ok!(received.len() == 2, "expected 2 bytes delivered to B, got {}", received.len());
    assert_ok!(received == b"AB", "delivered payload {:?} != expected {:?}", received, b"AB");

    Ok(())
}

// ── fin_in_ooo ───────────────────────────────────────────────────────────────
//
// RFC 9293 §3.10.7.4: segments queued out-of-order are processed after
// the gap is filled; a FIN in the OOO queue is deferred until then.
//
// OOO data and a FIN arrive while a gap exists.  Injecting the gap filler
// should let B drain OOO data, deliver it in order, then process the
// deferred FIN → CloseWait.
#[test]
fn fin_in_ooo() -> TestResult {
    use rawket::bridge::LinkProfile;
    let mut pair = setup_tcp_pair()
        .profile(LinkProfile::leased_line_100m())
        .connect();
    let (b_rcv_nxt, b_snd_nxt) = baseline_seqs(&mut pair)?;

    let ooo = a_to_b(&pair, b_rcv_nxt + 1, b_snd_nxt, b"B");
    pair.inject_to_b(ooo);
    pair.transfer_one();

    let fin = build_tcp_data_with_flags(
        pair.mac_a, pair.mac_b,
        pair.ip_a,  pair.ip_b,
        12345, 80,
        b_rcv_nxt + 2, b_snd_nxt,
        0x11, // FIN|ACK
        65535,
        b"",
    );
    pair.inject_to_b(fin);
    pair.transfer_one();

    // B should still be Established — FIN is deferred until gap is filled.
    assert_ok!(
        pair.tcp_b().state == State::Established,
        "B should still be Established before gap fill, got {:?}", pair.tcp_b().state
    );

    // Inject gap filler "A" at b_rcv_nxt and run to completion.
    let gap_fill = a_to_b(&pair, b_rcv_nxt, b_snd_nxt, b"A");
    pair.inject_to_b(gap_fill);
    let result = pair.transfer();

    // Data must be delivered in order before FIN processing.
    // "A" (gap fill) + "B" (OOO) = "AB".
    // (baseline "a" was consumed by drain_b in baseline_seqs.)
    let received = result.b.get(&0).map(|v| v.as_slice()).unwrap_or(&[]);
    assert_ok!(received.len() == 2, "expected 2 bytes delivered to B (A + B), got {}", received.len());
    assert_ok!(
        received == b"AB",
        "delivered payload {:?} != expected {:?} — OOO reorder before FIN incorrect",
        received, b"AB"
    );

    let b_state = pair.tcp_b().state;
    assert_ok!(
        b_state == State::CloseWait,
        "B expected CloseWait after gap fill resolved deferred FIN, got {b_state:?}"
    );

    Ok(())
}

// ── multiple_gaps_filled_in_order ────────────────────────────────────────────
//
// RFC 9293 §3.10.7.4: cumulative ACK advances as each gap is filled.
//
// OOO at +1 and +3; fill +0 then +2. Verify ACK advances past all 4 bytes.
#[test]
fn multiple_gaps_filled_in_order() -> TestResult {
    use rawket::bridge::LinkProfile;
    let mut pair = setup_tcp_pair()
        .profile(LinkProfile::leased_line_100m())
        .connect();
    let (b_rcv_nxt, b_snd_nxt) = baseline_seqs(&mut pair)?;

    for off in [1u32, 3] {
        let seg = a_to_b(&pair, b_rcv_nxt + off, b_snd_nxt, b"x");
        pair.inject_to_b(seg);
        pair.transfer_one();
    }

    let fill0 = a_to_b(&pair, b_rcv_nxt, b_snd_nxt, b"a");
    pair.inject_to_b(fill0);
    pair.transfer_one();

    let cap = pair.drain_captured();
    let ack_after_fill0 = cap.tcp()
        .direction(Dir::BtoA)
        .with_tcp_flags(TcpFlags::ACK)
        .map(|f| f.tcp.ack)
        .max();
    assert_ok!(
        ack_after_fill0 == Some(b_rcv_nxt + 2),
        "ACK should be exactly +2 after filling gap at +0"
    );

    let fill2 = a_to_b(&pair, b_rcv_nxt + 2, b_snd_nxt, b"c");
    pair.inject_to_b(fill2);
    pair.transfer_one();

    let cap2 = pair.drain_captured();
    let ack_after_fill2 = cap2.tcp()
        .direction(Dir::BtoA)
        .with_tcp_flags(TcpFlags::ACK)
        .map(|f| f.tcp.ack)
        .max();
    assert_ok!(
        ack_after_fill2 == Some(b_rcv_nxt + 4),
        "ACK should be exactly +4 after filling all gaps"
    );

    Ok(())
}

// ── ooo_duplicate_seq ────────────────────────────────────────────────────────
//
// RFC 2883 §3: D-SACK reports duplicate OOO segment via first SACK block.
//
// Inject a 2-byte OOO segment, then re-inject the first byte as a duplicate.
// D-SACK block 0 (duplicate) must be a strict subset of block 1 (full OOO range).
#[test]
fn ooo_duplicate_seq() -> TestResult {
    use rawket::bridge::LinkProfile;
    let mut pair = setup_tcp_pair()
        .profile(LinkProfile::leased_line_100m())
        .connect();
    let (b_rcv_nxt, b_snd_nxt) = baseline_seqs(&mut pair)?;

    // Inject a 2-byte OOO segment at offset+1.
    let seg = a_to_b(&pair, b_rcv_nxt + 1, b_snd_nxt, b"DE");
    pair.inject_to_b(seg);
    pair.transfer_one();
    pair.drain_captured();

    // Re-inject the first byte as a duplicate.
    let dup = a_to_b(&pair, b_rcv_nxt + 1, b_snd_nxt, b"D");
    pair.inject_to_b(dup);
    pair.transfer_one();

    // RFC 2883 §4 example 3: OOO D-SACK — first block (duplicate range)
    // is a strict subset of the second block (full OOO range).
    let cap = pair.drain_captured();
    let dsack_ack = cap.tcp()
        .direction(Dir::BtoA)
        .find(|f| f.tcp.opts.sack_blocks.len() >= 2);
    let dsack_ack = dsack_ack
        .ok_or_else(|| TestFail::new("expected ≥2 SACK blocks for OOO D-SACK after duplicate"))?;
    let blocks = &dsack_ack.tcp.opts.sack_blocks;
    // Block 0 (D-SACK): the duplicate byte [+1, +2).
    assert_ok!(
        blocks[0] == (b_rcv_nxt + 1, b_rcv_nxt + 2),
        "D-SACK block 0 should be [{}, {}), got [{}, {})",
        b_rcv_nxt + 1, b_rcv_nxt + 2, blocks[0].0, blocks[0].1
    );
    // Block 1: the full OOO range [+1, +3) — strictly larger than block 0.
    assert_ok!(
        blocks[1] == (b_rcv_nxt + 1, b_rcv_nxt + 3),
        "D-SACK block 1 should be [{}, {}), got [{}, {})",
        b_rcv_nxt + 1, b_rcv_nxt + 3, blocks[1].0, blocks[1].1
    );

    let fill = a_to_b(&pair, b_rcv_nxt, b_snd_nxt, b"C");
    pair.inject_to_b(fill);
    pair.transfer_one();

    let cap = pair.drain_captured();
    let max_ack = cap.tcp()
        .direction(Dir::BtoA)
        .map(|f| f.tcp.ack)
        .max();
    assert_ok!(
        max_ack == Some(b_rcv_nxt + 3),
        "ACK should be exactly +3 after gap fill with 2-byte OOO"
    );

    Ok(())
}

// ── ooo_segment_overlaps_rcv_nxt ─────────────────────────────────────────────
//
// RFC 9293 §3.10.7.4: segment starting before rcv_nxt but extending past it
// — trim the already-received portion; accept the new bytes.
#[test]
fn ooo_segment_overlaps_rcv_nxt() -> TestResult {
    use rawket::bridge::LinkProfile;
    let mut pair = setup_tcp_pair()
        .profile(LinkProfile::leased_line_100m())
        .connect();
    let (b_rcv_nxt, b_snd_nxt) = baseline_seqs(&mut pair)?;

    let overlap = a_to_b(
        &pair,
        b_rcv_nxt.wrapping_sub(2),
        b_snd_nxt,
        b"xyAB",
    );
    pair.inject_to_b(overlap);
    let result = pair.transfer();

    let cap = pair.drain_captured();
    let max_ack = cap.tcp()
        .direction(Dir::BtoA)
        .with_tcp_flags(TcpFlags::ACK)
        .map(|f| f.tcp.ack)
        .max();
    assert_ok!(
        max_ack == Some(b_rcv_nxt + 2),
        "B should have trimmed overlap and accepted 2 new bytes \
         (ack={:?}, expected={})", max_ack, b_rcv_nxt + 2
    );

    let got_ack = cap.tcp()
        .direction(Dir::BtoA)
        .with_tcp_flags(TcpFlags::ACK)
        .count() > 0;
    assert_ok!(got_ack, "B did not ACK the overlapping segment");

    // Verify only the new bytes ("AB") were delivered after trimming the
    // already-received prefix ("xy").
    // (baseline "a" was consumed by drain_b in baseline_seqs.)
    let received = result.b.get(&0).map(|v| v.as_slice()).unwrap_or(&[]);
    assert_ok!(received.len() == 2, "expected 2 bytes delivered to B (AB), got {}", received.len());
    assert_ok!(
        received == b"AB",
        "delivered payload {:?} != expected {:?} — overlap trim incorrect",
        received, b"AB"
    );

    Ok(())
}

// ── sack_reflects_all_holes ───────────────────────────────────────────────────
//
// RFC 2018 §3: SACK option lists all non-contiguous received blocks.
//
// 3 non-contiguous OOO segs → SACK blocks should cover all 3 ranges.
#[test]
fn sack_reflects_all_holes() -> TestResult {
    use rawket::bridge::LinkProfile;
    let mut pair = setup_tcp_pair()
        .profile(LinkProfile::leased_line_100m())
        .connect();
    let (b_rcv_nxt, b_snd_nxt) = baseline_seqs(&mut pair)?;

    for off in [1u32, 3, 5] {
        let seg = a_to_b(&pair, b_rcv_nxt + off, b_snd_nxt, b"x");
        pair.inject_to_b(seg);
        pair.transfer_one();
    }

    let cap = pair.drain_captured();
    let last_sack = cap.tcp()
        .direction(Dir::BtoA)
        .with_tcp_flags(TcpFlags::ACK)
        .filter(|f| f.tcp.opts.sack_blocks.len() >= 3)
        .last()
        .ok_or_else(|| crate::assert::TestFail::new("no ACK with ≥3 SACK blocks"))?;
    let blocks = &last_sack.tcp.opts.sack_blocks;
    assert_ok!(blocks.len() == 3, "expected 3 SACK blocks, got {}: {:?}", blocks.len(), blocks);

    // Exact 1-byte boundaries for OOO segments at offsets 1, 3, 5.
    for &off in &[1u32, 3, 5] {
        let has = blocks.iter().any(|&(l, r)| l == b_rcv_nxt + off && r == b_rcv_nxt + off + 1);
        assert_ok!(has, "SACK missing exact block for offset {off}: {:?}", blocks);
    }

    // Most recent (offset 5) must be first per RFC 2018 §4.
    assert_ok!(
        blocks[0] == (b_rcv_nxt + 5, b_rcv_nxt + 6),
        "first block {:?} should be most recent (offset 5)", blocks[0]
    );

    Ok(())
}

// ── drain_ooo_loop ────────────────────────────────────────────────────────────
//
// RFC 9293 §3.10.7.4: filling a gap drains consecutive OOO segments.
//
// Inject segs at +1, +2, +3; deliver +0 last. B's ACK should advance past +4.
#[test]
fn drain_ooo_loop() -> TestResult {
    use rawket::bridge::LinkProfile;
    let mut pair = setup_tcp_pair()
        .profile(LinkProfile::leased_line_100m())
        .connect();
    let (b_rcv_nxt, b_snd_nxt) = baseline_seqs(&mut pair)?;

    for off in [1u32, 2, 3] {
        let seg = a_to_b(&pair, b_rcv_nxt + off, b_snd_nxt, b"x");
        pair.inject_to_b(seg);
        pair.transfer_one();
    }

    pair.clear_capture();

    let fill = a_to_b(&pair, b_rcv_nxt, b_snd_nxt, b"x");
    pair.inject_to_b(fill);
    pair.transfer_one();

    let cap = pair.drain_captured();
    let max_ack = cap.tcp()
        .direction(Dir::BtoA)
        .map(|f| f.tcp.ack)
        .max();
    assert_ok!(
        max_ack == Some(b_rcv_nxt + 4),
        "B did not drain OOO buffer — ACK at {:?}, expected {}", max_ack, b_rcv_nxt + 4
    );

    Ok(())
}

// ── ooo_outside_window ─────────────────────────────────────────────────────
//
// RFC 9293 §3.10.7.4: segment with seq beyond the receive window must be
// dropped and not buffered in OOO.
#[test]
fn ooo_outside_window() -> TestResult {
    use rawket::bridge::LinkProfile;
    let mut pair = setup_tcp_pair()
        .profile(LinkProfile::leased_line_100m())
        .connect();
    let (b_rcv_nxt, b_snd_nxt) = baseline_seqs(&mut pair)?;

    let beyond = b_rcv_nxt + 2_000_000;
    let seg = a_to_b(&pair, beyond, b_snd_nxt, b"X");
    pair.inject_to_b(seg);
    pair.transfer_one();

    let cap = pair.drain_captured();

    // B should ACK with current rcv_nxt (segment dropped, not buffered).
    let ack = cap.tcp()
        .direction(Dir::BtoA)
        .with_tcp_flags(TcpFlags::ACK)
        .map(|f| f.tcp.ack)
        .max();
    assert_ok!(
        ack == Some(b_rcv_nxt),
        "B should ACK with rcv_nxt={b_rcv_nxt}, got {:?}", ack
    );

    // Dropped segment must not appear in SACK blocks.
    let has_sack = cap.tcp()
        .direction(Dir::BtoA)
        .any(|f| f.tcp.opts.sack_blocks.iter().any(|&(l, _)| l == beyond));
    assert_ok!(!has_sack, "OOO segment beyond window should not appear in SACK blocks");

    Ok(())
}
