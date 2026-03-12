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
    harness::{fast_tcp_cfg, setup_network_pair, setup_tcp_pair},
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
