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
    packet::{build_tcp_data, build_tcp_syn, build_icmp_frag_needed},
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

// RFC 9293 §3.7.1: if the MSS option is absent from the peer's SYN, the
// default MSS of 536 must be assumed; SYN-ACK SHOULD still carry MSS.
#[test]
fn mss_option_absent() -> TestResult {
    let mut np = setup_network_pair();
    let cfg = TcpConfig::default();

    let server = TcpSocket::accept(
        np.iface_b(),
        "10.0.0.2:80".parse().unwrap(),
        |_| {}, |_| {}, cfg,
    ).expect("accept");
    let ib = np.add_tcp_b(server);

    let isn_a = 0x1000_0000u32;
    let syn = build_tcp_syn(
        np.mac_a, np.mac_b,
        np.ip_a,  np.ip_b,
        12345, 80,
        isn_a, 0,
        0x02,
        None,   // no MSS option
        None, None, false,
    );
    // Drop RSTs from A (no A-side socket, so A would RST B's SYN-ACK).
    np.add_impairment_to_b(Impairment::Drop(PacketSpec::matching(filter::tcp::rst())));

    np.inject_to_b(syn);
    np.transfer_one();

    let syn_ack = np.drain_captured().tcp()
        .find(|f| f.dir == Dir::BtoA && f.tcp.flags.has(TcpFlags::SYN) && f.tcp.flags.has(TcpFlags::ACK))
        .ok_or_else(|| crate::assert::TestFail::new("no SYN-ACK from B"))?;

    // RFC 9293 §3.7.1: SYN-ACK SHOULD carry MSS option even when peer SYN omitted it.
    assert_ok!(
        syn_ack.tcp.opts.mss.is_some(),
        "SYN-ACK missing MSS option (RFC 9293 §3.7.1 SHOULD)"
    );

    let ack = build_tcp_data(
        np.mac_a, np.mac_b,
        np.ip_a,  np.ip_b,
        12345, 80,
        isn_a + 1,
        syn_ack.tcp.seq + 1,
        &[],
    );
    np.inject_to_b(ack);
    np.transfer_one();

    assert_state(np.tcp_b(ib), State::Established, "B state after handshake")?;
    np.clear_impairments();
    np.clear_capture();

    let big = vec![0xabu8; 2000];
    np.tcp_b_mut(ib).send(&big)?;
    np.transfer_one();

    let cap = np.drain_captured();
    let oversized = cap.tcp().filter(|f| f.dir == Dir::BtoA && f.payload_len > 536).count();
    assert_ok!(oversized == 0, "B sent {oversized} segments > 536 bytes despite peer advertising no MSS");

    let sent = cap.tcp().filter(|f| f.dir == Dir::BtoA && f.payload_len > 0).count();
    assert_ok!(sent > 0, "B sent no data segments");

    Ok(())
}

// RFC 1191 §3: upon receiving ICMP Fragmentation Needed, the sender must
// reduce its effective MSS to match the indicated next-hop MTU.
#[test]
fn pmtud_reduction() -> TestResult {
    use rawket::bridge::LinkProfile;
    let mut pair = setup_tcp_pair()
        .profile(LinkProfile::leased_line_100m())
        .connect();

    let chunk = vec![0xabu8; 1460];
    pair.tcp_a_mut().send(&chunk)?;
    pair.transfer();

    let orig_frame = pair.drain_captured().raw()
        .find(|f| f.dir == Dir::AtoB && !f.was_dropped)
        .map(|f| f.raw.clone())
        .ok_or_else(|| crate::assert::TestFail::new("no AtoB data frame found"))?;

    let icmp = build_icmp_frag_needed(
        pair.mac_b, pair.mac_a,
        pair.ip_b,  pair.ip_a,
        576,
        &orig_frame,
    );
    pair.inject_to_a(icmp);
    pair.transfer_one();

    let chunk2 = vec![0xcdu8; 2000];
    pair.tcp_a_mut().send(&chunk2)?;
    pair.transfer();

    let cap = pair.drain_captured();
    // MTU 576 → peer_mss 536; subtract 12 for timestamp option when active.
    let ts_overhead = if pair.tcp_a().ts_enabled() { 12 } else { 0 };
    let effective_mss = 536 - ts_overhead;
    let oversized = cap.tcp().filter(|f| f.dir == Dir::AtoB && f.payload_len > effective_mss).count();
    assert_ok!(oversized == 0, "A sent {oversized} segments > {effective_mss} bytes after PMTUD reduction to 576");

    let sent = cap.tcp().filter(|f| f.dir == Dir::AtoB && f.payload_len > 0).count();
    assert_ok!(sent > 0, "A sent no data segments after PMTUD update");

    Ok(())
}

// RFC 1191 §3: ICMP Fragmentation Needed must be matched to the correct
// flow; messages with non-matching ports must be ignored.
#[test]
fn pmtud_wrong_flow_ignored() -> TestResult {
    use rawket::bridge::LinkProfile;
    let mut pair = setup_tcp_pair()
        .profile(LinkProfile::leased_line_100m())
        .connect();

    pair.tcp_a_mut().send(&vec![0xabu8; 1460])?;
    pair.transfer();

    let mss_before = pair.tcp_a().peer_mss();

    let wrong_ports = build_tcp_data(
        pair.mac_a, pair.mac_b,
        pair.ip_a,  pair.ip_b,
        99, 99,
        0, 0,
        &[0u8; 100],
    );

    let icmp = build_icmp_frag_needed(
        pair.mac_b, pair.mac_a,
        pair.ip_b,  pair.ip_a,
        576,
        &wrong_ports,
    );
    pair.inject_to_a(icmp);
    pair.transfer_one();

    // MSS must be unchanged — wrong-flow ICMP is a complete no-op.
    let mss_after = pair.tcp_a().peer_mss();
    assert_ok!(
        mss_after == mss_before,
        "MSS changed after wrong-flow ICMP: before={mss_before}, after={mss_after}"
    );

    // Verify subsequent data uses the original MSS.
    pair.clear_capture();
    pair.tcp_a_mut().send(&vec![0xcdu8; 2000])?;
    pair.transfer();

    let cap = pair.drain_captured();
    let max_payload = cap.tcp()
        .filter(|f| f.dir == Dir::AtoB && f.payload_len > 0)
        .map(|f| f.payload_len)
        .max()
        .unwrap_or(0);
    // Max payload = MSS minus TCP timestamp option (12 bytes).
    assert_ok!(
        max_payload == mss_before as usize - 12,
        "post-ICMP max payload ({max_payload}) != original MSS - TS option ({} - 12 = {})",
        mss_before, mss_before - 12
    );

    Ok(())
}

// RFC 1191 §3: a subsequent ICMP with a larger MTU must not increase the
// path MTU — PMTUD only reduces, never raises.
#[test]
fn pmtud_no_increase() -> TestResult {
    use rawket::bridge::LinkProfile;
    let mut pair = setup_tcp_pair()
        .profile(LinkProfile::leased_line_100m())
        .connect();

    pair.tcp_a_mut().send(&vec![0xabu8; 1460])?;
    pair.transfer();

    let orig_frame = pair.drain_captured().raw()
        .find(|f| f.dir == Dir::AtoB && !f.was_dropped)
        .map(|f| f.raw.clone())
        .ok_or_else(|| crate::assert::TestFail::new("no AtoB data frame"))?;

    let icmp1 = build_icmp_frag_needed(
        pair.mac_b, pair.mac_a,
        pair.ip_b,  pair.ip_a,
        576,
        &orig_frame,
    );
    pair.inject_to_a(icmp1);
    pair.transfer_one();

    let icmp2 = build_icmp_frag_needed(
        pair.mac_b, pair.mac_a,
        pair.ip_b,  pair.ip_a,
        1000,
        &orig_frame,
    );
    pair.inject_to_a(icmp2);
    pair.transfer_one();

    pair.tcp_a_mut().send(&vec![0xcdu8; 2000])?;
    pair.transfer();

    let cap = pair.drain_captured();
    let ts_overhead = if pair.tcp_a().ts_enabled() { 12 } else { 0 };
    let effective_mss = 536 - ts_overhead;
    let oversized = cap.tcp().filter(|f| f.dir == Dir::AtoB && f.payload_len > effective_mss).count();
    assert_ok!(oversized == 0, "MSS increased after second larger ICMP ({oversized} segments > {effective_mss})");

    Ok(())
}

// RFC 1191 §3: "A host MUST never reduce its estimate of the Path MTU below
// 68 octets."  An ICMP with next-hop MTU=40 yields new_mss = 0 before
// clamping.  The implementation clamps to MIN_MSS = 28 (68 - 20 IP - 20 TCP).
// Verify peer_mss is reduced to 28 (not left at original, not set to 0).
#[test]
fn pmtud_floor() -> TestResult {
    use rawket::bridge::LinkProfile;
    let mut pair = setup_tcp_pair()
        .profile(LinkProfile::leased_line_100m())
        .connect();

    let original_mss = pair.tcp_a().peer_mss();

    pair.tcp_a_mut().send(&vec![0xabu8; 1460])?;
    pair.transfer();

    let orig_frame = pair.drain_captured().raw()
        .find(|f| f.dir == Dir::AtoB && !f.was_dropped)
        .map(|f| f.raw.clone())
        .ok_or_else(|| crate::assert::TestFail::new("no AtoB data frame"))?;

    // Inject ICMP Frag Needed with absurdly small MTU (40 = IP+TCP headers only).
    // new_mss = 40 - 20 - 20 = 0 before clamping → clamped to 28.
    let icmp = build_icmp_frag_needed(
        pair.mac_b, pair.mac_a,
        pair.ip_b,  pair.ip_a,
        40,
        &orig_frame,
    );
    pair.inject_to_a(icmp);
    pair.transfer_one();

    // RFC 1191 §3: PMTU clamped to 68 → MSS = 28.
    assert_ok!(
        pair.tcp_a().peer_mss() == 28,
        "peer_mss should be 28 (min PMTU=68 - 40 headers), got {}",
        pair.tcp_a().peer_mss()
    );

    // Verify A can still send data.
    pair.clear_capture();
    pair.tcp_a_mut().send(&vec![0xcdu8; 500])?;
    pair.transfer_one();

    let cap = pair.drain_captured();
    let sent = cap.tcp().filter(|f| f.dir == Dir::AtoB && f.payload_len > 0).count();
    assert_ok!(sent > 0, "A sent no data segments after absurd PMTUD");

    assert_state(pair.tcp_a(), State::Established, "A still Established after absurd PMTUD")?;

    Ok(())
}

// RFC 9293 §3.7.1: the effective MSS must account for TCP option overhead
// (e.g. 12 bytes for timestamps), not just the raw advertised MSS.
#[test]
fn effective_mss_accounts_for_ts_options() -> TestResult {
    use rawket::bridge::LinkProfile;
    let mut cfg = TcpConfig::default();
    cfg.mss = 536;

    let mut np = setup_network_pair().profile(LinkProfile::leased_line_100m());
    let client = TcpSocket::connect_now(
        np.iface_a(),
        "10.0.0.1:12345".parse().unwrap(),
        "10.0.0.2:80".parse().unwrap(),
        Ipv4Addr::from([10, 0, 0, 2]),
        |_| {}, |_| {}, cfg.clone(),
    ).expect("connect_now");
    let ia = np.add_tcp_a(client);

    let server = TcpSocket::accept(
        np.iface_b(),
        "10.0.0.2:80".parse().unwrap(),
        |_| {}, |_| {}, cfg,
    ).expect("accept");
    np.add_tcp_b(server);

    np.transfer();
    np.clear_capture();

    np.tcp_a_mut(ia).send(&vec![0xabu8; 2000])?;
    np.transfer();

    let cap = np.drain_captured();
    let oversized = cap.tcp().filter(|f| f.dir == Dir::AtoB && f.payload_len > 524).count();
    assert_ok!(oversized == 0, "A sent {oversized} segments > 524 bytes (peer_mss=536 minus 12 for TS)");

    let sent = cap.tcp().filter(|f| f.dir == Dir::AtoB && f.payload_len > 0).count();
    assert_ok!(sent > 0, "A sent no data segments");

    Ok(())
}
