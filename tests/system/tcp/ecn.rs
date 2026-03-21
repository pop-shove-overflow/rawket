use std::net::Ipv4Addr;
use rawket::{
    bridge::{Impairment, LinkProfile, PacketSpec},
    filter,
    tcp::{State, TcpConfig, TcpFlags, TcpSocket},
};
use crate::{
    assert::{assert_ect0, assert_state, TestFail},
    assert_ok,
    capture::ParsedFrameExt,
    harness::{setup_network_pair, setup_tcp_pair},
    packet::{build_tcp_data, build_tcp_syn, recompute_frame_tcp_checksum},
    TestResult,
};

/// Recompute the IP header checksum of a raw Ethernet frame in-place.
fn recompute_ip_checksum(frame: &mut [u8]) {
    frame[24] = 0;
    frame[25] = 0;
    let mut acc: u32 = 0;
    let mut i = 0usize;
    while i < 20 {
        acc += u16::from_be_bytes([frame[14 + i], frame[14 + i + 1]]) as u32;
        i += 2;
    }
    while acc >> 16 != 0 {
        acc = (acc & 0xffff) + (acc >> 16);
    }
    let csum = !(acc as u16);
    frame[24] = (csum >> 8) as u8;
    frame[25] = csum as u8;
}

// ── negotiation_active_active ─────────────────────────────────────────────────
//
// Both sides use default TcpConfig.  The SYN must carry ECE+CWR (active ECN open).
// The SYN-ACK must carry ECE but NOT CWR (per RFC 3168 §6.1.1).
#[test]
fn negotiation_active_active() -> TestResult {
    let (_pair, cap) = setup_tcp_pair()
        .profile(LinkProfile::leased_line_100m())
        .connect_and_capture();

    let syn = cap.tcp()
        .from_a()
        .with_tcp_flags(TcpFlags::SYN)
        .without_tcp_flags(TcpFlags::ACK)
        .next()
        .ok_or_else(|| TestFail::new("no SYN from A"))?;

    let syn_ack = cap.tcp()
        .from_b()
        .with_tcp_flags(TcpFlags::SYN)
        .with_tcp_flags(TcpFlags::ACK)
        .next()
        .ok_or_else(|| TestFail::new("no SYN-ACK from B"))?;

    // SYN: must have ECE+CWR.
    assert_ok!(
        syn.tcp.flags.has(TcpFlags::ECE) && syn.tcp.flags.has(TcpFlags::CWR),
        "SYN missing ECE+CWR flags (got {:?})", syn.tcp.flags
    );

    // SYN-ACK: must have ECE, must NOT have CWR.
    assert_ok!(
        syn_ack.tcp.flags.has(TcpFlags::ECE),
        "SYN-ACK missing ECE flag (got {:?})", syn_ack.tcp.flags
    );
    assert_ok!(
        !syn_ack.tcp.flags.has(TcpFlags::CWR),
        "SYN-ACK must not have CWR flag (got {:?})", syn_ack.tcp.flags
    );

    Ok(())
}


// ── ce_marking_ece_cwr ────────────────────────────────────────────────────────
//
// Full CE→ECE→CWR→cessation feedback loop per RFC 3168 §6.1:
//   1. B sends data, bridge marks it CE via Impairment::Congestion
//   2. A receives CE-marked data → echoes ECE on ACK
//   3. B receives ECE ACK → sends CWR on next data
//   4. A receives CWR → stops echoing ECE
#[test]
fn ce_marking_ece_cwr() -> TestResult {
    let mut pair = setup_tcp_pair()
        .profile(LinkProfile::leased_line_100m())
        .connect();

    // Warm up: exchange data so pacing gates are open.
    pair.tcp_a_mut().send(b"init")?;
    pair.transfer();
    pair.clear_capture();

    // Step 1: mark all B→A frames with CE (100% rate).
    pair.congestion_to_a(1.0);

    pair.tcp_b_mut().send(b"congested")?;
    pair.transfer();

    // Step 2: A receives CE-marked data → sends ACK with ECE.
    let cap = pair.drain_captured();
    let ece_sent = cap.tcp().from_a()
        .with_tcp_flags(TcpFlags::ACK)
        .any(|f| f.tcp.flags.has(TcpFlags::ECE));
    assert_ok!(ece_sent, "A did not echo ECE after receiving CE-marked data");

    // Remove congestion so subsequent frames are clean.
    pair.clear_impairments();
    pair.clear_capture();

    // Step 3: B receives ECE ACK → sends data with CWR.
    pair.advance_both(1000); // clear pacing gate
    pair.tcp_b_mut().send(b"cwr-response")?;
    pair.transfer();

    let cap = pair.drain_captured();
    let cwr_sent = cap.tcp().from_b().with_data()
        .any(|f| f.tcp.flags.has(TcpFlags::CWR));
    assert_ok!(cwr_sent, "B did not set CWR after receiving ECE");

    // Step 4: A receives CWR → stops echoing ECE on the very first ACK.
    pair.clear_capture();

    pair.tcp_b_mut().send(b"post-cwr")?;
    pair.transfer();

    let cap = pair.drain_captured();
    let first_ack_after_cwr = cap.tcp().from_a()
        .with_tcp_flags(TcpFlags::ACK)
        .next()
        .ok_or_else(|| TestFail::new("no ACK from A after CWR"))?;
    assert_ok!(
        !first_ack_after_cwr.tcp.flags.has(TcpFlags::ECE),
        "first ACK after CWR still has ECE — feedback loop not closed on first ACK"
    );

    // No subsequent ACKs should have ECE either.
    let still_ece = cap.tcp().from_a()
        .with_tcp_flags(TcpFlags::ACK)
        .any(|f| f.tcp.flags.has(TcpFlags::ECE));
    assert_ok!(
        !still_ece,
        "A still echoing ECE after receiving CWR — feedback loop not closed"
    );

    Ok(())
}

// ── ecn_disabled_if_not_supported ────────────────────────────────────────────
//
// RFC 3168 §6.1.1 (TCP Initialization): If the SYN-ACK does not carry ECE,
// the connection MUST fall back to non-ECN operation.
//
// Inject a SYN-ACK without ECE to A (simulating a non-ECN server).
// A must stay in Established without ECN, and must not set ECE/CWR on data.
#[test]
fn ecn_disabled_if_not_supported() -> TestResult {
    let mut np = setup_network_pair()
        .profile(LinkProfile::leased_line_100m());
    let cfg = TcpConfig::default();

    // Drop all BtoA frames so B's real SYN-ACK (with ECE) never reaches A.
    np.add_impairment_to_a(Impairment::Drop(PacketSpec::any()));

    let client = TcpSocket::connect_now(
        np.iface_a(),
        "10.0.0.1:12345".parse().unwrap(),
        "10.0.0.2:80".parse().unwrap(),
        Ipv4Addr::from([10, 0, 0, 2]),
        |_| {}, |_| {},
        cfg,
    )?;
    np.add_tcp_a(client);

    // Get A's ISN from its SYN (sent by connect_now).
    let cap = np.drain_captured();
    let a_isn = cap.tcp().from_a().with_tcp_flags(TcpFlags::SYN).next()
        .map(|f| f.tcp.seq)
        .ok_or_else(|| TestFail::new("no SYN from A"))?;

    // Inject synthetic SYN-ACK to A — no ECE flag, simulating an ECN-unaware peer.
    let isn_b = 0x5000_0000u32;
    let syn_ack = build_tcp_syn(
        np.mac_b, np.mac_a,
        np.ip_b,  np.ip_a,
        80, 12345,
        isn_b,
        a_isn + 1,
        0x12,       // SYN|ACK only, no ECE
        Some(1460),
        None, None, false,
    );
    np.clear_impairments();
    np.inject_to_a(syn_ack);
    np.transfer_one();

    assert_state(np.tcp_a(0), State::Established, "A state after non-ECN SYN-ACK")?;

    // A sends data; must not have ECE or CWR flags.
    np.clear_capture();
    np.tcp_a_mut(0).send(b"hello")?;
    np.transfer_one();

    let cap = np.drain_captured();
    let has_ecn = cap.tcp().from_a().with_data()
        .any(|f| f.tcp.flags.has(TcpFlags::ECE) || f.tcp.flags.has(TcpFlags::CWR));
    assert_ok!(
        !has_ecn,
        "A sent ECE/CWR on data frames despite ECN not being negotiated"
    );

    Ok(())
}

// ── cwr_sent_only_once ────────────────────────────────────────────────────────
//
// RFC 3168 §6.1.2 (The TCP Sender): The sender sets CWR on the first new data
// segment after receiving ECE, then clears it — CWR is sent only once per
// congestion event.
//
// After A receives an ECE-flagged ACK from B (B signals congestion), A sets
// ecn_cwr_needed.  A's first new data segment must carry CWR.  The second
// data segment must NOT carry CWR (flag sent only once per congestion event).
#[test]
fn cwr_sent_only_once() -> TestResult {
    let mut pair = setup_tcp_pair()
        .profile(LinkProfile::leased_line_100m())
        .connect();

    pair.tcp_a_mut().send(b"hello")?;
    pair.transfer();

    let cap = pair.drain_captured();
    let af = cap.tcp().from_a().with_data().next()
        .ok_or_else(|| TestFail::new("no AtoB data frame"))?;
    let a_snd_nxt = af.tcp.seq + af.payload_len as u32;
    let b_seq = cap.tcp().from_b().next().map(|f| f.tcp.seq).unwrap_or(0);

    pair.clear_capture();
    let (mac_b, mac_a, ip_b, ip_a) = (pair.mac_b, pair.mac_a, pair.ip_b, pair.ip_a);

    // Inject ACK from B with ECE flag set (B signals network congestion).
    let mut ece_ack = crate::packet::build_tcp_data_with_ts(
        mac_b, mac_a, ip_b, ip_a,
        80, 12345,
        b_seq, a_snd_nxt,
        0, 0, // patched by inject_to_a
        b"",
    );
    ece_ack[47] |= 0x40; // set ECE bit
    recompute_frame_tcp_checksum(&mut ece_ack);
    pair.inject_to_a(ece_ack);
    pair.transfer_one();

    // Prove ECE was accepted (ecn_cwr_needed should be set).
    assert_ok!(
        pair.tcp_a().ecn_enabled(),
        "ECN not enabled — ECE ACK may have been rejected"
    );

    // A now has ecn_cwr_needed = true.  First data segment must have CWR.
    pair.advance_both(1000);
    pair.tcp_a_mut().send(b"x")?;
    pair.transfer();

    let cap = pair.drain_captured();
    let first_data_cwr = cap.tcp().from_a().with_data().next()
        .map(|f| f.tcp.flags.has(TcpFlags::CWR));
    assert_ok!(
        first_data_cwr == Some(true),
        "first data segment from A after ECE should have CWR flag"
    );

    pair.clear_capture();

    // Second data segment must NOT have CWR (flag cleared after first send).
    pair.advance_both(1000);
    pair.tcp_a_mut().send(b"y")?;
    pair.transfer();

    let cap = pair.drain_captured();
    let second_data_cwr = cap.tcp().from_a().with_data().next()
        .map(|f| f.tcp.flags.has(TcpFlags::CWR));
    assert_ok!(
        second_data_cwr == Some(false),
        "second data segment from A should NOT have CWR flag (sent only once)"
    );

    Ok(())
}

// ── ect_bits_on_data_segments ───────────────────────────────────────────────
//
// RFC 3168 §6.1.2 (The TCP Sender): "ECT(0) SHOULD be used" when only one
// ECT codepoint is needed.  Our implementation always uses ECT(0).
#[test]
fn ect_bits_on_data_segments() -> TestResult {
    let mut pair = setup_tcp_pair()
        .profile(LinkProfile::leased_line_100m())
        .connect();

    // Send data from both sides.
    pair.tcp_a_mut().send(b"hello")?;
    pair.tcp_b_mut().send(b"world")?;
    pair.transfer();

    let cap = pair.drain_captured();

    // A's outgoing data must carry ECT(0).
    let a_data: Vec<_> = cap.tcp().from_a().with_data().collect();
    assert_ok!(!a_data.is_empty(), "no AtoB data frames");
    for f in &a_data {
        assert_ect0(f, "A→B data segment")?;
    }

    // B's outgoing data must also carry ECT(0).
    let b_data: Vec<_> = cap.tcp().from_b().with_data().collect();
    assert_ok!(!b_data.is_empty(), "no BtoA data frames");
    for f in &b_data {
        assert_ect0(f, "B→A data segment")?;
    }

    Ok(())
}

// ── no_ect_bits_when_disabled ───────────────────────────────────────────────
//
// RFC 3168 §6.1.1 (TCP Initialization): after receiving a non-ECN-setup
// SYN-ACK, a host "SHOULD NOT set ECT on data packets."  Our implementation
// enforces this as MUST NOT.
#[test]
fn no_ect_bits_when_disabled() -> TestResult {
    let mut np = setup_network_pair()
        .profile(LinkProfile::leased_line_100m());
    let cfg = TcpConfig::default();

    // Drop all BtoA so A never gets SYN-ACK.
    np.add_impairment_to_a(Impairment::Drop(PacketSpec::any()));

    let client = TcpSocket::connect_now(
        np.iface_a(),
        "10.0.0.1:12345".parse().unwrap(),
        "10.0.0.2:80".parse().unwrap(),
        Ipv4Addr::from([10, 0, 0, 2]),
        |_| {}, |_| {},
        cfg,
    )?;
    np.add_tcp_a(client);

    let cap = np.drain_captured();
    let a_isn = cap.all_tcp().from_a().with_tcp_flags(TcpFlags::SYN).next()
        .map(|f| f.tcp.seq)
        .ok_or_else(|| TestFail::new("no SYN from A"))?;

    // Inject SYN-ACK without ECE (non-ECN peer).
    let isn_b = 0x6000_0000u32;
    let syn_ack = build_tcp_syn(
        np.mac_b, np.mac_a,
        np.ip_b,  np.ip_a,
        80, 12345,
        isn_b, a_isn + 1,
        0x12,       // SYN|ACK, no ECE
        Some(1460), None, None, false,
    );
    np.clear_impairments();
    np.inject_to_a(syn_ack);
    np.transfer_one();

    assert_state(np.tcp_a(0), State::Established, "A Established after non-ECN handshake")?;

    np.clear_capture();
    np.tcp_a_mut(0).send(b"hello")?;
    np.transfer_one();

    let cap = np.drain_captured();
    let data_frames: Vec<_> = cap.tcp().from_a().with_data().collect();
    assert_ok!(
        !data_frames.is_empty(),
        "no data frames captured — ECN bit check would be vacuous"
    );

    for f in &data_frames {
        assert_ok!(
            f.ip_ecn == etherparse::IpEcn::NotEct,
            "data frame has ECN bits {:?} but ECN is disabled (expected NotEct)", f.ip_ecn
        );
    }

    Ok(())
}

// ── ece_triggers_cwnd_reduction ─────────────────────────────────────────────
//
// RFC 3168 §6.1.2 (The TCP Sender): upon receiving ECE, "the TCP source
// halves the congestion window 'cwnd' and reduces the slow start threshold."
// Send enough data to grow cwnd above the 4*MSS floor before injecting ECE.
// Inject an ECE-flagged ACK directly to A to simulate B signalling congestion.
#[test]
fn ece_triggers_cwnd_reduction() -> TestResult {
    let mut pair = setup_tcp_pair().profile(LinkProfile::leased_line_100m()).connect();

    // Phase 1: grow cwnd above 4*MSS floor.
    pair.tcp_a_mut().send(&[0xAAu8; 50_000])?;
    pair.transfer();

    let cwnd_before = pair.tcp_a().bbr_cwnd();
    let mss = pair.tcp_a().peer_mss() as u32;
    assert_ok!(
        cwnd_before > 4 * mss,
        "cwnd ({cwnd_before}) did not grow above 4*MSS ({}) — test scenario invalid",
        4 * mss
    );
    assert_ok!(pair.tcp_a().ecn_enabled(), "ECN not negotiated — test scenario invalid");

    // Phase 2: send fresh data to get current seq/ack values.
    pair.tcp_a_mut().send(&[0xBBu8; 10_000])?;
    pair.transfer();

    let cap = pair.drain_captured();
    let af = cap.tcp().from_a().with_data().last()
        .ok_or_else(|| TestFail::new("no A→B data in phase 2"))?;
    let a_snd_nxt = af.tcp.seq + af.payload_len as u32;
    let b_seq = cap.tcp().from_b().last().map(|f| f.tcp.seq).unwrap_or(0);

    pair.clear_capture();
    let (mac_b, mac_a, ip_b, ip_a) = (pair.mac_b, pair.mac_a, pair.ip_b, pair.ip_a);

    // Phase 3: inject ECE ACK directly to A.
    // Use snd_una as ack_num (a pure ACK — all data has been ACKed by now).
    // A will still process the ECE flag even on a zero-window-update ACK.
    let ece_ack_num = pair.tcp_a().snd_una();
    let mut ece_ack = build_tcp_data(
        mac_b, mac_a, ip_b, ip_a,
        80, 12345,
        b_seq,
        ece_ack_num,
        b"",
    );
    let _ = a_snd_nxt;
    ece_ack[47] |= 0x40; // set ECE bit
    recompute_frame_tcp_checksum(&mut ece_ack);
    pair.inject_to_a(ece_ack);
    pair.transfer_one();

    // Phase 4: verify CWR on next data + drive until cwnd reduces.
    pair.clear_capture();
    pair.advance_both(1000);
    pair.tcp_a_mut().send(&[0xCCu8; 20_000])?;

    let mut cwnd_reduced = false;
    pair.transfer_while(|p| {
        if p.tcp_a(0).send_buf_len() == 0 {
            let _ = p.tcp_a_mut(0).send(&[0xCCu8; 2_000]);
        }
        let cwnd_now = p.tcp_a(0).bbr_cwnd();
        if cwnd_now < cwnd_before {
            cwnd_reduced = true;
            return false;
        }
        true
    });

    let cap_cwr = pair.drain_captured();
    let cwr_set = cap_cwr.tcp().from_a().with_data()
        .any(|f| f.tcp.flags.has(TcpFlags::CWR));
    assert_ok!(
        cwr_set,
        "A did not set CWR on data after ECE — no congestion response"
    );

    assert_ok!(
        cwnd_reduced,
        "cwnd not reduced after ECE: before={cwnd_before}"
    );

    Ok(())
}

// ── no_ect_on_syn ─────────────────────────────────────────────────────────
//
// RFC 3168 §6.1.1: SYN and SYN-ACK MUST NOT carry ECT bits in the IP
// header (only TCP flags ECE/CWR are used for negotiation).
#[test]
fn no_ect_on_syn() -> TestResult {
    let (_pair, cap) = setup_tcp_pair()
        .profile(LinkProfile::leased_line_100m())
        .connect_and_capture();

    // Guard: at least 1 SYN and 1 SYN-ACK must be present.
    let syns: Vec<_> = cap.tcp().with_tcp_flags(TcpFlags::SYN).collect();
    let syn_count = syns.iter().filter(|f| !f.tcp.flags.has(TcpFlags::ACK)).count();
    let syn_ack_count = syns.iter().filter(|f| f.tcp.flags.has(TcpFlags::ACK)).count();
    assert_ok!(syn_count >= 1, "no SYN found — test would be vacuous");
    assert_ok!(syn_ack_count >= 1, "no SYN-ACK found — test would be vacuous");

    // Check all SYN and SYN-ACK frames for ECT bits.
    for f in &syns {
        assert_ok!(
            f.ip_ecn == etherparse::IpEcn::NotEct,
            "SYN/SYN-ACK IP ECN = {:?}, expected NotEct (no ECT on handshake)", f.ip_ecn
        );
    }

    Ok(())
}

// ── ece_persists_until_cwr ────────────────────────────────────────────
//
// RFC 3168 §6.1.3: the receiver MUST set ECE on every ACK until it
// receives a segment with the CWR flag from the sender.
//
// Inject a CE-marked frame to B so B starts echoing ECE.  Drop all
// A→B data (so CWR never reaches B).  Verify B's subsequent ACKs
// continue to carry ECE.
#[test]
fn ece_persists_until_cwr() -> TestResult {
    let mut pair = setup_tcp_pair()
        .profile(LinkProfile::leased_line_100m())
        .connect();

    pair.tcp_a_mut().send(b"hello")?;
    pair.transfer();

    // Use live socket state for seq numbers (captures may not reflect final state).
    let b_rcv_nxt = pair.tcp_b().rcv_nxt();
    let b_snd_nxt = pair.tcp_b().snd_nxt();

    pair.clear_capture();
    let (mac_a, mac_b, ip_a, ip_b) = (pair.mac_a, pair.mac_b, pair.ip_a, pair.ip_b);

    // Inject a CE-marked data frame to B (ECN bits = 0x03 = CE).
    let mut ce_frame = build_tcp_data(
        mac_a, mac_b, ip_a, ip_b,
        12345, 80,
        b_rcv_nxt,
        b_snd_nxt,
        b"X",
    );
    ce_frame[15] = (ce_frame[15] & 0xFC) | 0x03; // Set CE in IP ECN field
    recompute_ip_checksum(&mut ce_frame);
    recompute_frame_tcp_checksum(&mut ce_frame);
    pair.inject_to_b(ce_frame);
    pair.transfer_one();

    // B's ACK should have ECE set.
    let cap = pair.drain_captured();
    let first_ece = cap.tcp().from_b()
        .with_tcp_flags(TcpFlags::ACK)
        .any(|f| f.tcp.flags.has(TcpFlags::ECE));
    assert_ok!(first_ece, "B did not set ECE after receiving CE-marked frame");

    // Now drop all A→B data so CWR never reaches B.
    pair.add_impairment_to_b(Impairment::Drop(PacketSpec::matching(filter::tcp::has_data())));

    // Inject more data to B to elicit additional ACKs.
    pair.clear_capture();
    for i in 0..3u8 {
        let data = build_tcp_data(
            mac_a, mac_b, ip_a, ip_b,
            12345, 80,
            b_rcv_nxt + 1 + i as u32,
            b_snd_nxt,
            &[0x60 + i],
        );
        pair.inject_to_b(data);
        pair.transfer_one();
    }

    // All of B's ACKs must still carry ECE (CWR was never received).
    let cap = pair.drain_captured();
    let acks: Vec<bool> = cap.tcp().from_b()
        .with_tcp_flags(TcpFlags::ACK)
        .map(|f| f.tcp.flags.has(TcpFlags::ECE))
        .collect();
    assert_ok!(
        !acks.is_empty(),
        "no ACKs from B after injecting data"
    );
    let all_ece = acks.iter().all(|&has_ece| has_ece);
    assert_ok!(
        all_ece,
        "B stopped echoing ECE before receiving CWR — \
         RFC 3168 §6.1.3 requires ECE on every ACK until CWR; \
         ECE flags: {acks:?}"
    );

    Ok(())
}

// ── pure_ack_no_ect ───────────────────────────────────────────────────────
//
// RFC 3168 §6.1.4: Pure ACKs (no data) MUST NOT have ECT bits set, since
// they cannot be dropped by ECN-capable routers.
#[test]
fn pure_ack_no_ect() -> TestResult {
    let mut pair = setup_tcp_pair()
        .profile(LinkProfile::leased_line_100m())
        .connect();

    // Send data from A so B generates pure ACKs.
    pair.tcp_a_mut().send(b"hello-ecn")?;
    pair.transfer();

    let cap = pair.drain_captured();
    let pure_acks: Vec<_> = cap.tcp().from_b()
        .filter(|f| f.tcp.flags.has(TcpFlags::ACK) && f.payload_len == 0
            && !f.tcp.flags.has(TcpFlags::SYN) && !f.tcp.flags.has(TcpFlags::FIN))
        .collect();
    assert_ok!(!pure_acks.is_empty(), "no pure ACKs from B — test would be vacuous");

    for f in &pure_acks {
        assert_ok!(
            f.ip_ecn == etherparse::IpEcn::NotEct,
            "pure ACK has ECN bits {:?}, expected NotEct (RFC 3168 §6.1.4)", f.ip_ecn
        );
    }

    Ok(())
}
