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

// ── isn_spread_same_tuple ─────────────────────────────────────────────────────
//
// RFC 6528 §3: ISN = M + F(localip, localport, remoteip, remoteport, key).
// The spread threshold of 1000 is an implementation heuristic — RFC 6528
// does not define a minimum pairwise distance.  Our getrandom(2)-based
// ISN produces much larger separation in practice.
//
// 5 connections on the same 4-tuple; all ISNs must be distinct with
// pairwise spread > 1000.
#[test]
fn isn_spread_same_tuple() -> TestResult {
    use rawket::bridge::LinkProfile;
    let mut np = setup_network_pair()
        .profile(LinkProfile::leased_line_100m());
    let cfg = TcpConfig::default();
    let mut isns: Vec<u32> = Vec::new();

    for _ in 0..5 {
        let client = TcpSocket::connect_now(
            np.iface_a(),
            "10.0.0.1:12345".parse().unwrap(),
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
            .expect("no SYN found");
        isns.push(isn);
    }

    let mut deduped = isns.clone();
    deduped.sort_unstable();
    deduped.dedup();
    assert_ok!(
        deduped.len() == isns.len(),
        "rapid reconnect ISNs overlap: {:?}", isns
    );

    let mut min_diff = u32::MAX;
    for i in 0..isns.len() {
        for j in (i + 1)..isns.len() {
            let diff = isns[i].wrapping_sub(isns[j]).min(isns[j].wrapping_sub(isns[i]));
            if diff < min_diff { min_diff = diff; }
        }
    }
    // Implementation heuristic: spread > 1000 catches degenerate ISN
    // generators (e.g., counter with small increment).  RFC 6528 §3 does not
    // define a minimum pairwise distance.  Our getrandom(2)-based ISN
    // produces much larger separation in practice.
    assert_ok!(
        min_diff > 1000,
        "ISN spread too small (min pairwise diff = {min_diff}): {:?}", isns
    );

    Ok(())
}

// ── syn_collision_ack_numbers ─────────────────────────────────────────────────
//
// RFC 9293 §3.5: during simultaneous open, each SYN+ACK must acknowledge
// the peer's ISN (ack = peer ISN + 1).
#[test]
fn syn_collision_ack_numbers() -> TestResult {
    use rawket::bridge::LinkProfile;
    let mut np = setup_network_pair()
        .profile(LinkProfile::leased_line_100m());
    let cfg = TcpConfig::default();

    let client_a = TcpSocket::connect_now(
        np.iface_a(),
        "10.0.0.1:12345".parse().unwrap(),
        "10.0.0.2:80".parse().unwrap(),
        Ipv4Addr::from([10, 0, 0, 2]),
        |_| {}, |_| {},
        cfg.clone(),
    ).expect("A connect_now");
    np.add_tcp_a(client_a);

    let client_b = TcpSocket::connect_now(
        np.iface_b(),
        "10.0.0.2:80".parse().unwrap(),
        "10.0.0.1:12345".parse().unwrap(),
        Ipv4Addr::from([10, 0, 0, 1]),
        |_| {}, |_| {},
        cfg,
    ).expect("B connect_now");
    np.add_tcp_b(client_b);

    let cap0 = np.drain_captured();
    let a_isn = cap0.tcp()
        .direction(Dir::AtoB)
        .with_tcp_flags(TcpFlags::SYN)
        .without_tcp_flags(TcpFlags::ACK)
        .next()
        .map(|f| f.tcp.seq)
        .expect("no SYN from A");
    let b_isn = cap0.tcp()
        .direction(Dir::BtoA)
        .with_tcp_flags(TcpFlags::SYN)
        .without_tcp_flags(TcpFlags::ACK)
        .next()
        .map(|f| f.tcp.seq)
        .expect("no SYN from B");

    np.transfer();

    let cap1 = np.drain_captured();
    let a_synack_ack = cap1.tcp()
        .direction(Dir::AtoB)
        .with_tcp_flags(TcpFlags::SYN)
        .with_tcp_flags(TcpFlags::ACK)
        .next()
        .map(|f| f.tcp.ack);
    let b_synack_ack = cap1.tcp()
        .direction(Dir::BtoA)
        .with_tcp_flags(TcpFlags::SYN)
        .with_tcp_flags(TcpFlags::ACK)
        .next()
        .map(|f| f.tcp.ack);

    let a_ack = a_synack_ack.ok_or_else(|| crate::assert::TestFail::new(
        "no SYN+ACK from A during simultaneous open"
    ))?;
    let b_ack = b_synack_ack.ok_or_else(|| crate::assert::TestFail::new(
        "no SYN+ACK from B during simultaneous open"
    ))?;

    assert_ok!(
        a_ack == b_isn.wrapping_add(1),
        "A's SYN+ACK ack ({a_ack}) != B's ISN+1 ({})", b_isn.wrapping_add(1)
    );
    assert_ok!(
        b_ack == a_isn.wrapping_add(1),
        "B's SYN+ACK ack ({b_ack}) != A's ISN+1 ({})", a_isn.wrapping_add(1)
    );

    Ok(())
}
