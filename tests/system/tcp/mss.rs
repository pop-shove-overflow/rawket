#![allow(dead_code, unused_imports)]
use rawket::tcp::{TcpFlags, TcpSocket, State};
use rawket::bridge::{Impairment, PacketSpec};
use rawket::filter;
use std::net::Ipv4Addr;
use crate::{
    TestResult, assert_ok,
    assert::{assert_mss_option, assert_state},
    capture::{Dir, ParsedFrameExt},
    harness::{fast_tcp_cfg, setup_network_pair, setup_tcp_pair},
    packet::{build_tcp_data, build_tcp_syn, build_icmp_frag_needed, build_icmp_generic},
};

// RFC 9293 §3.7.1: both SYN and SYN-ACK carry an MSS option; data segments
// must not exceed the negotiated MSS.
#[test]
fn negotiation_normal() -> TestResult {
    use rawket::bridge::LinkProfile;
    let (mut pair, cap) = setup_tcp_pair()
        .profile(LinkProfile::leased_line_100m())
        .connect_and_capture();

    let syn = cap.tcp()
        .find(|f| f.dir == Dir::AtoB && f.tcp.flags.has(TcpFlags::SYN) && !f.tcp.flags.has(TcpFlags::ACK))
        .ok_or_else(|| crate::assert::TestFail::new("no SYN from A"))?;

    let syn_ack = cap.tcp()
        .find(|f| f.dir == Dir::BtoA && f.tcp.flags.has(TcpFlags::SYN) && f.tcp.flags.has(TcpFlags::ACK))
        .ok_or_else(|| crate::assert::TestFail::new("no SYN-ACK from B"))?;

    assert_mss_option(&syn,     1460, "SYN MSS")?;
    assert_mss_option(&syn_ack, 1460, "SYN-ACK MSS")?;

    // Verify data segments are capped at negotiated MSS.
    let mss = pair.tcp_a().peer_mss() as usize;
    pair.tcp_a_mut().send(&vec![0xAAu8; mss * 3])?;
    pair.transfer();

    let cap = pair.drain_captured();
    let oversized = cap.tcp().from_a().with_data()
        .filter(|f| f.payload_len > mss)
        .count();
    assert_ok!(
        oversized == 0,
        "{oversized} data segment(s) exceed negotiated MSS ({mss})"
    );

    Ok(())
}
