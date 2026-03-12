use std::net::Ipv4Addr;
use rawket::{
    bridge::{Impairment, LinkProfile, PacketSpec},
    filter,
    tcp::{State, TcpFlags, TcpSocket},
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
