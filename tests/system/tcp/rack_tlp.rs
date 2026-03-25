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

// RFC 8985 §7.3: TLP sends a probe segment when no ACK arrives within the
// PTO interval. Drop B's first ACK so A never receives acknowledgement.
// TLP fires after 2*srtt, sending a retransmit probe. B ACKs. A is Established.
//
// Uses a leased-line profile so the handshake establishes SRTT > 0.
// RFC 8985 §7.2 provides a 1-second fallback when SRTT is unavailable;
// our implementation requires SRTT > 0 to arm TLP.
#[test]
fn tlp_tail_loss() -> TestResult {
    // rto_min_ms=200 ensures RTO >> PTO so TLP fires first.
    let mut pair = setup_tcp_pair().rto_min_ms(200).profile(LinkProfile::leased_line_100m()).connect();

    // Warm up SRTT with a data exchange.
    pair.tcp_a_mut().send(b"warmup")?;
    pair.transfer();
    pair.clear_capture();

    let srtt = pair.tcp_a().srtt_ms();
    assert_ok!(srtt > 0, "SRTT not established after warmup");

    // Drop B's first ACK so data stays unacked → TLP fires.
    // nth_matching(1, ack) drops only the first ACK; TLP probe's ACK gets through.
    pair.add_impairment_to_a(Impairment::Drop(PacketSpec::nth_matching(1, filter::tcp::ack())));
    pair.tcp_a_mut().send(&[0xbbu8; 100])?;

    // transfer() drives: data→B, B's ACK dropped, TLP fires, B ACKs probe (2nd ACK goes through).
    pair.transfer();

    // Count AtoB data frames with same seq — expect ≥2 (original + TLP probe).
    let cap = pair.drain_captured();
    let seg_seq = cap.tcp().from_a().with_data().next()
        .map(|f| f.tcp.seq)
        .ok_or_else(|| TestFail::new("no AtoB data frame"))?;
    let tlp_frames: Vec<_> = cap.all_tcp().from_a().with_data()
        .filter(|f| f.tcp.seq == seg_seq)
        .collect();
    assert_ok!(
        tlp_frames.len() >= 2,
        "expected ≥2 AtoB data frames with seg_seq={seg_seq} (original+TLP), got {}",
        tlp_frames.len()
    );

    // RFC 8985 §7.2: PTO = 2*SRTT; += WCDelAckT when FlightSize == 1.
    // FlightSize is 1 (single 100-byte segment), so PTO = 2*SRTT + WCDelAck.
    let wc_del_ack_ms = rawket::tcp::WC_DEL_ACK_NS / 1_000_000;
    let original = &tlp_frames[0];
    let probe = tlp_frames.last().unwrap();
    let gap_ms = (probe.ts_ns - original.ts_ns) / 1_000_000;
    let pto_ms = 2 * srtt + wc_del_ack_ms;
    let rto = pair.tcp_a().rto_ms();
    // TLP must fire at PTO (before RTO).
    assert_ok!(
        gap_ms >= pto_ms.saturating_sub(5) && gap_ms < rto,
        "TLP gap {gap_ms}ms not near PTO ({pto_ms}ms) or >= RTO ({rto}ms) — \
         expected PTO = 2*SRTT({srtt}) + {wc_del_ack_ms}ms WCDelAck"
    );

    // RFC 7323 §3.2: TLP probe must carry timestamps.
    assert_timestamps_present(probe, "TLP probe")?;

    Ok(())
}

// RFC 8985 §7.3: After TLP probe is acknowledged, A must be Established and able to send.
#[test]
fn tlp_probe_advances_connection() -> TestResult {
    let mut pair = setup_tcp_pair()
        .rto_min_ms(10)
        .profile(LinkProfile::leased_line_100m())
        .connect();

    pair.tcp_a_mut().send(b"advance-test-data")?;
    pair.transfer_one();

    let snd_una_before = pair.tcp_a().snd_una();

    // Drop B's first ACK — nth_matching(1) only drops the first.
    pair.add_impairment_to_a(Impairment::Drop(PacketSpec::nth_matching(1, filter::tcp::ack())));

    // transfer() drives: data→B, B's ACK dropped, TLP fires, B ACKs probe (2nd ACK goes through).
    pair.transfer();

    let snd_una_after = pair.tcp_a().snd_una();
    assert_ok!(
        snd_una_after != snd_una_before,
        "snd_una did not advance after TLP probe (before={snd_una_before}, after={snd_una_after})"
    );

    assert_ok!(
        pair.tcp_a().state == rawket::tcp::State::Established,
        "A not Established after TLP: {:?}", pair.tcp_a().state
    );

    // A can still send.
    pair.tcp_a_mut().send(b"ok")?;
    pair.transfer();

    assert_ok!(
        pair.tcp_a().state == rawket::tcp::State::Established,
        "A not Established after post-TLP send: {:?}", pair.tcp_a().state
    );

    Ok(())
}

// RFC 8985: RACK should detect multiple losses within a single window.
// Drop segments #1 and #2 (both consecutive); verify A retransmits both.
#[test]
fn multiple_losses_detected() -> TestResult {
    let mut pair = setup_tcp_pair()
        .profile(LinkProfile::leased_line_100m())
        .connect();

    // Seed BBR/SRTT.
    pair.tcp_a_mut().send(b"init-phase-data-xxxx")?;
    pair.transfer();
    pair.clear_capture();

    // Drop the first 2 data segments.
    pair.add_impairment_to_b(Impairment::Drop(PacketSpec::nth_matching(1, filter::tcp::has_data())));
    pair.add_impairment_to_b(Impairment::Drop(PacketSpec::nth_matching(1, filter::tcp::has_data())));

    // Send enough for 3+ segments. Impairments drop during transfer, then exhaust.
    // After both nth_matching(1) fire, remaining segments + retransmits go through.
    pair.tcp_a_mut().send(&[0xaau8; 5000])?;
    pair.transfer();

    assert_ok!(
        pair.tcp_a().state == rawket::tcp::State::Established,
        "A not Established after multiple losses: {:?}", pair.tcp_a().state
    );

    // Verify data was eventually delivered (retransmits happened).
    let cap = pair.drain_captured();
    let total_data: usize = cap.tcp().from_a().with_data().map(|f| f.payload_len).sum();
    assert_ok!(total_data >= 3000, "expected ≥3000 bytes delivered after loss recovery, got {total_data}");

    // Verify ≥2 segments were dropped and both retransmitted.
    let dropped_seqs: Vec<u32> = cap.all_tcp().from_a().dropped().with_data()
        .map(|f| f.tcp.seq)
        .collect();
    assert_ok!(
        dropped_seqs.len() >= 2,
        "expected ≥2 dropped segments, got {}: {:?}", dropped_seqs.len(), dropped_seqs
    );
    for &seq in &dropped_seqs {
        let retx = cap.all_tcp().from_a().delivered().with_data()
            .filter(|f| f.tcp.seq == seq)
            .count();
        assert_ok!(retx >= 1, "dropped segment seq={seq} was never retransmitted");
    }

    Ok(())
}

// RFC 8985: RACK end_seq/xmit_ms must be updated from SACK-covered segments.
// Drop first segment, verify rack_end_seq advances after SACK feedback.
#[test]
fn rack_updates_from_sack() -> TestResult {
    let mut pair = setup_tcp_pair()
        .profile(LinkProfile::leased_line_100m())
        .connect();

    // Seed BBR/SRTT.
    pair.tcp_a_mut().send(b"seed-data-xxxxxxxxx")?;
    pair.transfer();
    pair.clear_capture();

    let rack_end_before  = pair.tcp_a().rack_end_seq();
    let rack_xmit_before = pair.tcp_a().rack_xmit_ns();

    // Drop first data segment, send data + more data for SACK feedback.
    pair.add_impairment_to_b(Impairment::Drop(PacketSpec::nth_matching(1, filter::tcp::has_data())));
    pair.tcp_a_mut().send(&[0xbbu8; 200])?;
    pair.tcp_a_mut().send(&[0xccu8; 200])?;
    pair.transfer();

    assert_ok!(
        pair.tcp_a().state == rawket::tcp::State::Established,
        "A not Established after SACK-based RACK recovery: {:?}", pair.tcp_a().state
    );

    // RACK state must have advanced past the recovered segment.
    let rack_end_after  = pair.tcp_a().rack_end_seq();
    let rack_xmit_after = pair.tcp_a().rack_xmit_ns();
    assert_ok!(
        rack_end_after > rack_end_before,
        "RACK end_seq did not advance after SACK feedback: {rack_end_before}->{rack_end_after}"
    );
    assert_ok!(
        rack_xmit_after > rack_xmit_before,
        "RACK xmit_ns did not advance after SACK feedback: {rack_xmit_before}->{rack_xmit_after}"
    );
    // rack_end_seq should cover at least the end of the second segment
    // (the one that was SACKed, triggering loss detection of the first).
    let snd_nxt = pair.tcp_a().snd_nxt();
    assert_ok!(
        rack_end_after >= snd_nxt.wrapping_sub(200),
        "RACK end_seq ({rack_end_after}) didn't reach the SACKed segment range"
    );

    // Verify the dropped segment was retransmitted.
    let cap = pair.drain_captured();
    let dropped_seqs: Vec<u32> = cap.all_tcp().from_a().dropped().with_data()
        .map(|f| f.tcp.seq)
        .collect();
    assert_ok!(!dropped_seqs.is_empty(), "no segments were dropped — test scenario invalid");
    for &seq in &dropped_seqs {
        let retx = cap.all_tcp().from_a().delivered().with_data()
            .filter(|f| f.tcp.seq == seq)
            .count();
        assert_ok!(retx >= 1, "dropped segment seq={seq} not retransmitted via SACK-based RACK");
    }

    Ok(())
}

// RFC 8985 §7.2: PTO is capped so it does not exceed the RTO expiration.
// With SRTT==0, our implementation uses a 10ms TLP fallback (RFC 8985 §7.2
// specifies 1 second; this is an implementation-specific choice).
// Set rto_min=5ms so RTO(5ms) < TLP fallback(10ms). Verify RTO fires first.
#[test]
fn tlp_not_if_rto_sooner() -> TestResult {
    let mut np = setup_network_pair();
    let cfg = TcpConfig::default().rto_min_ms(5);
    let rto_min = cfg.rto_min_ms as i64;

    let client = TcpSocket::connect_now(
        np.iface_a(),
        "10.0.0.1:12345".parse().unwrap(),
        "10.0.0.2:80".parse().unwrap(),
        Ipv4Addr::from([10, 0, 0, 2]),
        |_| {}, |_| {},
        cfg.clone(),
    )?;
    np.add_tcp_a(client);

    let server = TcpSocket::accept(
        np.iface_b(),
        "10.0.0.2:80".parse().unwrap(),
        |_| {}, |_| {}, cfg,
    )?;
    np.add_tcp_b(server);

    np.transfer_one();
    np.transfer_one();
    np.transfer_one();
    np.clear_capture();

    // Precondition: instant link produces no RTT sample during handshake,
    // so SRTT==0 and TLP uses the implementation's 10ms fallback (RFC 8985
    // §7.2 specifies 1 second; see header comment).  If SRTT > 0, TLP
    // deadline = 2*SRTT which may be < rto_min, breaking the test.
    let srtt = np.tcp_a(0).srtt_ms();
    assert_ok!(srtt == 0, "SRTT should be 0 after instant-link handshake, got {srtt} ms");

    // Drop all A→B data.
    np.add_impairment_to_b(Impairment::Drop(PacketSpec::matching(filter::tcp::has_data())));

    np.tcp_a_mut(0).send(b"rto-vs-tlp")?;
    np.transfer_one();

    // Advance past RTO but before TLP fallback(10ms).
    np.advance_both(rto_min + 2);
    np.transfer_one();

    // Count dropped data frames: expect 2 (original + RTO retransmit).
    let cap = np.drain_captured();
    let count_after_rto = cap.all_tcp().from_a().dropped().with_data().count();
    assert_ok!(
        count_after_rto == 2,
        "expected 2 dropped data frames after RTO (original + retransmit), got {count_after_rto}; \
         TLP may have fired despite RTO being sooner (RFC 8985 §7.3 violation)"
    );

    // Advance past TLP(10ms) but before backed-off RTO (2*rto_min): no new frames.
    np.advance_both(rto_min);
    np.transfer_one();

    let cap2 = np.drain_captured();
    let count_at_12 = cap2.all_tcp().from_a().dropped().with_data().count();
    assert_ok!(
        count_at_12 == 0,
        "extra retransmit(s) at t=7..12ms ({count_at_12}) — TLP not disarmed by RTO"
    );

    Ok(())
}

// RFC 8985 §3.3.2: reo_wnd adapts after D-SACK events.  The decay formula
// (reo_wnd -= reo_wnd/8 + 1 per round) is implementation-specific; RFC 8985
// uses a reo_wnd_mult/reo_wnd_persist counter mechanism instead.
#[test]
fn rack_reo_wnd_decay() -> TestResult {
    let mut pair = setup_tcp_pair().profile(LinkProfile::leased_line_100m()).connect();

    // Warm up BBR.
    pair.tcp_a_mut().send(&[0xaau8; 1000])?;
    pair.transfer();

    pair.clear_capture();
    pair.tcp_a_mut().send(&[0xbbu8; 100])?;
    pair.transfer();

    let cap = pair.drain_captured();
    let bta = cap.tcp().from_b().last()
        .ok_or_else(|| TestFail::new("no B→A ACK frame for D-SACK setup"))?;
    let (b_seq, a_snd_una) = (bta.tcp.seq, bta.tcp.ack);
    let (b_src_port, a_dst_port) = (bta.src_port, bta.dst_port);

    // Inject D-SACK.
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

    let reo_wnd_after_dsack = pair.tcp_a().rack_reo_wnd_ns();
    assert_ok!(reo_wnd_after_dsack > 0, "reo_wnd should be >0 after D-SACK, got {reo_wnd_after_dsack}");

    // Drive clean ACK rounds — each send+transfer completes a round.
    let mut reo_samples = vec![reo_wnd_after_dsack];
    for _ in 0..20 {
        pair.tcp_a_mut().send(&[0xccu8; 100])?;
        pair.transfer();
        reo_samples.push(pair.tcp_a().rack_reo_wnd_ns());
    }

    let reo_wnd_after_decay = *reo_samples.last().unwrap();
    assert_ok!(
        reo_wnd_after_decay < reo_wnd_after_dsack,
        "reo_wnd did not decay: after_dsack={reo_wnd_after_dsack}, after={reo_wnd_after_decay}"
    );

    // Verify decay rate: reo_wnd -= reo_wnd/8 + 1 per round.
    // Check consecutive pairs where decay actually occurred (reo_wnd changed).
    let mut verified_decays = 0;
    for w in reo_samples.windows(2) {
        let (prev, cur) = (w[0], w[1]);
        if prev == cur || prev == 0 { continue; }
        let expected_decay = prev.saturating_sub(prev / 8 + 1);
        assert_ok!(
            cur == expected_decay,
            "reo_wnd decay mismatch: {prev} -> {cur}, expected {expected_decay} \
             (prev - prev/8 - 1); samples: {reo_samples:?}"
        );
        verified_decays += 1;
    }
    assert_ok!(
        verified_decays >= 3,
        "too few decay steps verified ({verified_decays}); samples: {reo_samples:?}"
    );

    assert_ok!(
        pair.tcp_a().state == rawket::tcp::State::Established,
        "A not Established: {:?}", pair.tcp_a().state
    );

    Ok(())
}

// RFC 8985 §7.3: TLP retransmits the last unacked segment (verified by seq number match).
//
// Uses a leased-line profile so the handshake establishes SRTT > 0 —
// TLP is only armed when SRTT is known.
#[test]
fn tlp_probe_is_tail_segment() -> TestResult {
    let mut pair = setup_tcp_pair().profile(LinkProfile::leased_line_100m()).connect();

    // Warm up SRTT with a data exchange.
    pair.tcp_a_mut().send(b"warmup")?;
    pair.transfer();
    pair.clear_capture();

    let srtt = pair.tcp_a().srtt_ms();
    assert_ok!(srtt > 0, "SRTT not established after warmup");

    // Drop B's first ACK so TLP fires. nth_matching(1) only drops the first.
    pair.add_impairment_to_a(Impairment::Drop(PacketSpec::nth_matching(1, filter::tcp::ack())));
    pair.tcp_a_mut().send(b"tail-probe-test")?;

    // transfer() drives: data→B, B's ACK dropped, TLP fires, B ACKs probe.
    pair.transfer();

    // Collect all AtoB data frames — expect original + TLP probe.
    let cap = pair.drain_captured();
    let data_seq = cap.tcp().from_a().with_data().next()
        .map(|f| f.tcp.seq)
        .ok_or_else(|| TestFail::new("no AtoB data"))?;
    let probe_count = cap.all_tcp().from_a().delivered().with_data()
        .filter(|f| f.tcp.seq == data_seq)
        .count();

    // Expect ≥2: the original send + at least one TLP probe retransmit.
    assert_ok!(
        probe_count >= 2,
        "expected ≥2 frames with seq={data_seq} (original + TLP probe), got {probe_count}"
    );

    // RFC 7323 §3.2: TLP probe must carry timestamps.
    let probe = cap.all_tcp().from_a().delivered().with_data()
        .filter(|f| f.tcp.seq == data_seq)
        .last()
        .ok_or_else(|| TestFail::new("no TLP probe frame found"))?;
    assert_timestamps_present(&probe, "TLP probe")?;

    Ok(())
}

// RFC 8985 §6.2 (Upon Receiving an ACK): RACK-detected losses feed into
// congestion control. After
// sustained loss triggers bbr_on_loss, verify BBR reduced cwnd from peak.
// Use 20% uniform loss on a latency link to reliably trigger RACK loss detection.
#[test]
fn rack_loss_triggers_bbr_on_loss() -> TestResult {
    // Clean handshake on leased-line, then add 20% loss.
    // max_retransmits=100 prevents connection death under sustained 20% loss.
    let mut pair = setup_tcp_pair()
        .max_retransmits(100)
        .rto_max_ms(200)
        .profile(LinkProfile::leased_line_100m())
        .connect();
    pair.loss_to_b(0.20);

    pair.tcp_a_mut().send(&[0xaau8; 80_000])?;

    let mut peak_cwnd: u32 = 0;
    let mut cwnd_reduced = false;

    pair.transfer_while(|p| {
        let cwnd = p.tcp_a(0).bbr_cwnd();
        if cwnd > peak_cwnd {
            peak_cwnd = cwnd;
        } else if peak_cwnd > 0 && cwnd < peak_cwnd {
            cwnd_reduced = true;
            return false;
        }

        if p.tcp_a(0).send_buf_len() < 10_000 {
            let _ = p.tcp_a_mut(0).send(&[0xaau8; 20_000]);
        }
        true
    });

    assert_ok!(
        pair.tcp_a().state == rawket::tcp::State::Established,
        "A not Established after RACK loss: {:?}", pair.tcp_a().state
    );
    assert_ok!(
        cwnd_reduced,
        "cwnd never reduced during sustained 20% loss (peak={peak_cwnd}) — \
         RACK-detected loss should trigger BBR congestion response"
    );

    Ok(())
}

// Numerical verification of the RACK time-based threshold per RFC 8985 §6.2.
//
// RACK declares a segment lost when:
//   now >= seg.last_sent_ns + rack_rtt + reorder_window
// where reorder_window = min_rtt/4 on a clean link (no D-SACK).
//
// To isolate the time criterion from the packet-count criterion (≥3 SACKed
// after hole), we send exactly two segments — one dropped, one delivered —
// staggered in time by more than reo_wnd so the time check fires on the
// first SACK.
#[test]
fn rack_threshold_formula() -> TestResult {
    // Stable 100 Mbps / 10 ms one-way → 20 ms RTT, no jitter.
    let mut pair = setup_tcp_pair()
        .profile(LinkProfile::leased_line_100m())
        .connect();

    // Phase 1: seed RTT with a lossless transfer.
    pair.tcp_a_mut().send(&[0xAAu8; 5000])?;
    pair.transfer();

    let min_rtt_ms = pair.tcp_a().bbr_min_rtt_ns() / 1_000_000;
    assert_ok!(min_rtt_ms > 0, "no RTT sample — test scenario invalid");

    // reo_wnd = min_rtt/4 = 5 ms.  Stagger seg1→seg2 by reo_wnd + 5 ms
    // so the time criterion fires when seg2's SACK arrives.
    let reo_wnd_ms = (min_rtt_ms / 4).max(1);
    let stagger_ms = reo_wnd_ms + 5;

    // Phase 2: two staggered segments — seg1 dropped, seg2 delivered.
    // Only 1 segment SACKed after hole → packet-count criterion (≥3) cannot
    // fire, isolating the time-based threshold.
    pair.clear_capture();
    pair.drop_next_data_to_b();
    pair.tcp_a_mut().send(&[0xBBu8; 1460])?;     // seg1 (dropped)
    pair.advance_both(stagger_ms as i64);
    pair.tcp_a_mut().send(&[0xCCu8; 1460])?;     // seg2 (delivered)
    pair.transfer();

    // Find dropped seg1 and its RACK retransmit (same seq).
    let cap = pair.drain_captured();
    let dropped = cap.all_tcp().from_a().dropped().with_data().next()
        .ok_or_else(|| TestFail::new("no dropped segment — impairment didn't fire"))?;
    let retx = cap.all_tcp().from_a().delivered().with_data()
        .find(|f| f.tcp.seq == dropped.tcp.seq)
        .ok_or_else(|| TestFail::new(
            "RACK retransmit never delivered — time criterion may not have fired"
        ))?;

    // Gap = stagger + RTT (seg2 must traverse to B and SACK must return).
    // Expected: stagger_ms + min_rtt_ms.
    let gap = retx.ms_since(&dropped);
    let expected = stagger_ms + min_rtt_ms;
    assert_ok!(
        gap >= expected - 2 && gap <= expected + 2,
        "RACK retransmit gap {gap}ms outside [{}, {}]ms \
         (stagger={stagger_ms}ms, min_rtt={min_rtt_ms}ms, expected={expected}ms)",
        expected - 2, expected + 2
    );

    Ok(())
}
