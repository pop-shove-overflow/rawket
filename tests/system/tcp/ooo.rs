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
