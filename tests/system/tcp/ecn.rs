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
// Inject a CE-marked data frame from B to A.  A processes the CE-marked IP
// frame and sets ecn_ce_pending.  A's next ACK (sent in response to B's
// in-order data) must have the ECE flag.
