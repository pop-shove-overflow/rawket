use rawket::{
    bridge::{Impairment, LinkProfile, Loss, PacketSpec},
    filter,
    tcp::TcpSocket,
};
use crate::{
    assert::{TestFail, assert_timestamps_present},
    assert_ok,
    capture::ParsedFrameExt,
    harness::{setup_network_pair, setup_tcp_pair},
    packet::build_tcp_data_with_sack_ts,
    TestResult,
};
use std::net::Ipv4Addr;

// RFC 8985 §6.2 (Upon Receiving an ACK): RACK detects loss when a higher-seq
// segment is ACKed but a lower-seq segment is still unacked. Drop seg2, let
// seg3 through, verify A retransmits seg2.
#[test]
fn rack_basic_loss_detection() -> TestResult {
    let mut pair = setup_tcp_pair()
        .profile(LinkProfile::leased_line_100m())
        .connect();

    // Phase 1: seed BBR/SRTT.
    pair.tcp_a_mut().send(b"seg1-data-xxxxxxxxxx")?;
    pair.transfer();
    pair.clear_capture();

    let rack_end_before = pair.tcp_a().rack_end_seq();

    // Drop the 1st data segment from A (seg2).
    pair.add_impairment_to_b(Impairment::Drop(PacketSpec::nth_matching(1, filter::tcp::has_data())));

    // Send seg2+seg3, clear impairments, then transfer drives SACK→RACK recovery.
    pair.tcp_a_mut().send(b"seg2-dropped-xxxxxxx")?;
    pair.tcp_a_mut().send(b"seg3-xxxxxxxxxxxxxxxxx")?;
    pair.clear_impairments();
    pair.transfer();

    // Verify seg2 appeared at least twice (original dropped + RACK retransmit).
    let cap = pair.drain_captured();
    let seg2_seq = cap.all_tcp()
        .from_a()
        .dropped()
        .with_data()
        .next()
        .map(|f| f.tcp.seq)
        .ok_or_else(|| TestFail::new("no dropped AtoB data frame for seg2"))?;

    let seg2_count = cap.all_tcp().from_a().with_data()
        .filter(|f| f.tcp.seq == seg2_seq)
        .count();
    assert_ok!(
        seg2_count >= 2,
        "expected ≥2 frames with seg2 seq={seg2_seq} (dropped+RACK retransmit), got {seg2_count}"
    );

    // Verify retransmit was delivered (not dropped).
    let delivered = cap.all_tcp().from_a().delivered().with_data()
        .filter(|f| f.tcp.seq == seg2_seq)
        .count();
    assert_ok!(
        delivered >= 1,
        "RACK retransmit of seg2 seq={seg2_seq} was never delivered"
    );

    assert_ok!(
        pair.tcp_a().state == rawket::tcp::State::Established,
        "A not Established after RACK retransmit: {:?}", pair.tcp_a().state
    );

    // RACK state must have advanced past the recovered segment.
    let rack_end_after = pair.tcp_a().rack_end_seq();
    assert_ok!(
        rack_end_after > rack_end_before,
        "rack_end_seq did not advance after RACK loss detection: before={rack_end_before}, after={rack_end_after}"
    );

    // The retransmit was triggered by RACK, not RTO.  Proof:
    // 1. rack_end_seq advanced (checked above)
    // 2. B sent a SACK indicating the gap
    // 3. Retransmit timing: from original send to retransmit must be < RTO.
    //    RACK fires after SACK arrival (~1 RTT) + reo_wnd (min_rtt/4),
    //    which is ~1.25 RTT — well under RTO.
    let sack_count = cap.tcp().from_b()
        .filter(|f| f.tcp.opts.sack_blocks.len() > 0)
        .count();
    assert_ok!(sack_count > 0, "no SACK from B — RACK had no loss signal");

    let original_ts = cap.all_tcp().from_a().dropped().with_data()
        .find(|f| f.tcp.seq == seg2_seq)
        .map(|f| f.ts_ns);
    let retx_ts = cap.all_tcp().from_a().delivered().with_data()
        .find(|f| f.tcp.seq == seg2_seq)
        .map(|f| f.ts_ns);
    assert_ok!(original_ts.is_some(), "dropped seg2 timestamp missing");
    assert_ok!(retx_ts.is_some(), "retransmit seg2 timestamp missing");
    let gap_ms = (retx_ts.unwrap() - original_ts.unwrap()) / 1_000_000;
    let rto = pair.tcp_a().rto_ms();
    assert_ok!(
        gap_ms < rto,
        "original→retransmit gap {gap_ms}ms >= RTO ({rto}ms) — looks like RTO, not RACK"
    );

    Ok(())
}

// RFC 8985 §3.3.2 (Reordering Window Adaptation): reorder window adapts after
// D-SACK events. Inject D-SACK to A, verify reo_wnd increased from its
// initial value.
#[test]
fn rack_reorder_window_adapts() -> TestResult {
    let mut pair = setup_tcp_pair().profile(LinkProfile::leased_line_100m()).connect();

    // Seed SRTT + BW with clean exchanges.
    pair.tcp_a_mut().send(&[0x55u8; 1000])?;
    pair.transfer();

    pair.clear_capture();
    pair.tcp_a_mut().send(&[0x66u8; 100])?;
    pair.transfer();

    let cap = pair.drain_captured();
    let bta = cap.tcp().from_b().last()
        .ok_or_else(|| TestFail::new("no B→A ACK frame found for D-SACK setup"))?;
    let (b_seq, a_snd_una) = (bta.tcp.seq, bta.tcp.ack);
    let (b_src_port, a_dst_port) = (bta.src_port, bta.dst_port);

    let reo_wnd_before = pair.tcp_a().rack_reo_wnd_ns();

    // Inject D-SACK: SACK block below snd_una triggers spurious retransmit detection.
    let dsack = build_tcp_data_with_sack_ts(
        pair.mac_b, pair.mac_a,
        pair.ip_b,  pair.ip_a,
        b_src_port, a_dst_port,
        b_seq, a_snd_una,
        0, 0, // timestamps patched by inject_to_a
        &[(a_snd_una.wrapping_sub(100), a_snd_una)],
        &[],
    );
    pair.inject_to_a(dsack);
    pair.transfer_one();

    let reo_wnd_after = pair.tcp_a().rack_reo_wnd_ns();
    assert_ok!(reo_wnd_after > 0, "RACK reo_wnd is 0 after D-SACK — should have been bumped");
    assert_ok!(
        reo_wnd_after > reo_wnd_before,
        "RACK reo_wnd did not increase after D-SACK: before={reo_wnd_before}, after={reo_wnd_after}"
    );

    // Implementation-specific: D-SACK increments reo_wnd by min_rtt/4 (capped
    // at SRTT).  RFC 8985 §6.2 step 4 uses a reo_wnd_mult counter instead.
    let min_rtt_ns = pair.tcp_a().bbr_min_rtt_ns();
    let srtt_ns = pair.tcp_a().srtt_ns();
    let expected_inc = (min_rtt_ns / 4).max(1);
    let expected = (reo_wnd_before + expected_inc).min(srtt_ns);
    assert_ok!(
        reo_wnd_after == expected,
        "reo_wnd after D-SACK = {reo_wnd_after} ns, expected {expected} ns \
         (before={reo_wnd_before} + min_rtt/4={expected_inc}, cap=srtt={srtt_ns})"
    );

    assert_ok!(
        pair.tcp_a().state == rawket::tcp::State::Established,
        "A not Established after D-SACK: {:?}", pair.tcp_a().state
    );

    Ok(())
}
