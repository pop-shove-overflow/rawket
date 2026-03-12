use std::net::Ipv4Addr;
use rawket::tcp::{State, TcpConfig, TcpFlags, TcpSocket};
use crate::{
    assert_ok,
    capture::{Dir, ParsedFrameExt},
    harness::setup_network_pair,
    TestResult,
};

// ── unique_per_connection ─────────────────────────────────────────────────────
//
// RFC 6528 §3: ISN generation must produce distinct values across connections
// sharing the same PRNG generator, not just across fresh stacks.
//
// 10 connections on the same NetworkPair with varying src_port; all ISNs must
// be distinct.
#[test]
fn unique_per_connection() -> TestResult {
    use rawket::bridge::LinkProfile;
    let mut np = setup_network_pair()
        .profile(LinkProfile::leased_line_100m());
    let cfg = TcpConfig::default();
    let mut isns: Vec<u32> = Vec::new();

    for i in 0..10u16 {
        let src_port = 10000 + i;
        let client = TcpSocket::connect_now(
            np.iface_a(),
            format!("10.0.0.1:{src_port}").parse().unwrap(),
            "10.0.0.2:80".parse().unwrap(),
            Ipv4Addr::from([10, 0, 0, 2]),
            |_| {}, |_| {},
            cfg.clone(),
        ).expect("connect_now");
        np.add_tcp_a(client);

        let cap = np.drain_captured();
        let isn = cap.tcp()
            .direction(Dir::AtoB)
            .with_tcp_flags(TcpFlags::SYN)
            .without_tcp_flags(TcpFlags::ACK)
            .next()
            .map(|f| f.tcp.seq)
            .expect("no SYN found in capture");
        isns.push(isn);
    }

    let mut deduped = isns.clone();
    deduped.sort_unstable();
    deduped.dedup();
    assert_ok!(
        deduped.len() == isns.len(),
        "ISNs are not all unique: {:?}", isns
    );

    Ok(())
}

// ── simultaneous_open ────────────────────────────────────────────────────────
//
// Both endpoints call connect_now (no server listen). Each sends SYN, receives
// peer SYN → SynReceived, sends SYN+ACK. Both reach Established.
