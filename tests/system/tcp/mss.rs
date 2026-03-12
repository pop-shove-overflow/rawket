#![allow(dead_code, unused_imports)]
use rawket::tcp::{TcpConfig, TcpFlags, TcpSocket, State};
use rawket::bridge::{Impairment, PacketSpec};
use rawket::filter;
use std::net::Ipv4Addr;
use crate::{
    TestResult, assert_ok,
    assert::{assert_mss_option, assert_state},
    capture::{Dir, ParsedFrameExt},
    harness::{setup_network_pair, setup_tcp_pair},
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

// RFC 9293 §3.7.1: the sender must segment data at the peer's advertised MSS,
// not its own.
#[test]
fn negotiation_smaller_peer() -> TestResult {
    use rawket::bridge::LinkProfile;
    let mut cfg_a = TcpConfig::default();
    cfg_a.mss = 1460;
    let mut cfg_b = TcpConfig::default();
    cfg_b.mss = 512;

    // We need B to use cfg_b (512). The builder uses the same cfg for both sides.
    // Build manually with setup_network_pair instead.

    let mut np = setup_network_pair().profile(LinkProfile::leased_line_100m());
    let client = TcpSocket::connect_now(
        np.iface_a(),
        "10.0.0.1:12345".parse().unwrap(),
        "10.0.0.2:80".parse().unwrap(),
        Ipv4Addr::from([10, 0, 0, 2]),
        |_| {}, |_| {}, cfg_a,
    ).expect("connect_now");
    let ia = np.add_tcp_a(client);

    let server = TcpSocket::accept(
        np.iface_b(),
        "10.0.0.2:80".parse().unwrap(),
        |_| {}, |_| {}, cfg_b,
    ).expect("accept");
    np.add_tcp_b(server);

    np.transfer();

    let cap = np.drain_captured();

    let syn_ack = cap.tcp()
        .find(|f| f.dir == Dir::BtoA && f.tcp.flags.has(TcpFlags::SYN) && f.tcp.flags.has(TcpFlags::ACK))
        .ok_or_else(|| crate::assert::TestFail::new("no SYN-ACK from B"))?;
    assert_mss_option(&syn_ack, 512, "SYN-ACK MSS")?;

    np.clear_capture();

    // Send 1000 bytes from A — must be chunked into ≤ 512-byte segments.
    let big = vec![0xabu8; 1000];
    np.tcp_a_mut(ia).send(&big)?;
    np.transfer();

    let cap2 = np.drain_captured();
    let oversized = cap2.tcp().filter(|f| f.dir == Dir::AtoB && f.payload_len > 512).count();
    assert_ok!(oversized == 0, "A sent {oversized} segments larger than B's MSS of 512");

    let total: usize = cap2.tcp().filter(|f| f.dir == Dir::AtoB && f.payload_len > 0).map(|f| f.payload_len).sum();
    assert_ok!(total >= 1000, "total bytes from A ({total}) < 1000");

    Ok(())
}

