// Checksum validation tests.
//
// rawket has per-protocol RX checksum validation flags:
//   - Enabled by `setup_tcp_pair()` → `test_network_config()`
//   - Disabled by `.net_config(NetworkConfig::default)` → `NetworkConfig::default()`
//
// TCP checksum offset:
//   Ethernet(14) + IPv4(20) + TCP_offset(16) = byte 50
//   (same whether or not timestamps are present)

use rawket::{bridge::LinkProfile, network::NetworkConfig, tcp::State};
use crate::{
    assert::assert_state,
    assert_ok,
    harness::{build_network_pair, setup_network_pair, setup_tcp_pair},
    packet::{build_tcp_data, build_udp_data},
    TestResult,
};

const IP_CSUM_BYTE: usize = 24;  // Ethernet(14) + IP header checksum offset(10)
const TCP_CSUM_BYTE: usize = 50; // Ethernet(14) + IPv4(20) + TCP checksum offset(16)
const UDP_CSUM_BYTE: usize = 40; // Ethernet(14) + IPv4(20) + UDP checksum offset(6)

fn make_data_frame(pair: &crate::harness::TcpSocketPair) -> Vec<u8> {
    let a_snd_nxt = pair.tcp_a().snd_nxt();
    let a_rcv_nxt = pair.tcp_a().rcv_nxt();
    build_tcp_data(
        pair.mac_a, pair.mac_b,
        pair.ip_a,  pair.ip_b,
        12345, 80,
        a_snd_nxt,
        a_rcv_nxt,
        b"X",
    )
}

// ── tcp_bad_checksum_dropped ──────────────────────────────────────────────────
//
// RFC 9293 §3.1: The TCP checksum covers the pseudo-header + segment; receivers
// MUST discard segments with invalid checksums.
//
// With checksum_validate_tcp=true, a corrupted TCP checksum must be dropped.
#[test]
fn tcp_bad_checksum_dropped() -> TestResult {
    let mut pair = setup_tcp_pair()
        .profile(LinkProfile::leased_line_100m())
        .connect();

    let rcv_nxt_before = pair.tcp_b().rcv_nxt();

    // Corrupt high byte.
    let mut frame = make_data_frame(&pair);
    frame[TCP_CSUM_BYTE] ^= 0xFF;
    pair.inject_to_b(frame);
    pair.transfer_one();

    let rcv_nxt_after = pair.tcp_b().rcv_nxt();
    assert_ok!(
        rcv_nxt_after == rcv_nxt_before,
        "B accepted segment with bad TCP checksum high byte (rcv_nxt advanced {} → {})",
        rcv_nxt_before, rcv_nxt_after
    );

    // Corrupt low byte.
    let mut frame = make_data_frame(&pair);
    frame[TCP_CSUM_BYTE + 1] ^= 0xFF;
    pair.inject_to_b(frame);
    pair.transfer_one();

    let rcv_nxt_after = pair.tcp_b().rcv_nxt();
    assert_ok!(
        rcv_nxt_after == rcv_nxt_before,
        "B accepted segment with bad TCP checksum low byte (rcv_nxt advanced {} → {})",
        rcv_nxt_before, rcv_nxt_after
    );
    Ok(())
}

// ── tcp_checksum_accepted_when_disabled ───────────────────────────────────────
//
// RFC 9293 §3.1: TCP checksum validation is mandatory per the spec, but our
// stack exposes a config knob to disable it (e.g. for hardware offload paths).
//
// With checksum_validate_tcp=false, a corrupted checksum must still be accepted.
#[test]
fn tcp_checksum_accepted_when_disabled() -> TestResult {
    let mut pair = setup_tcp_pair()
        .net_config(NetworkConfig::default)
        .profile(LinkProfile::leased_line_100m())
        .connect();

    let rcv_nxt_before = pair.tcp_b().rcv_nxt();

    let mut frame = make_data_frame(&pair);
    frame[TCP_CSUM_BYTE] ^= 0xFF;
    pair.inject_to_b(frame);
    pair.transfer_one();

    assert_state(
        pair.tcp_b(),
        State::Established,
        "B still Established after accepting bad-checksum segment",
    )?;
    let rcv_nxt_after = pair.tcp_b().rcv_nxt();
    let advanced = rcv_nxt_after.wrapping_sub(rcv_nxt_before) < 0x8000_0000;
    assert_ok!(
        advanced && rcv_nxt_after != rcv_nxt_before,
        "B dropped segment with bad TCP checksum despite validation being disabled \
         (rcv_nxt stayed at {})",
        rcv_nxt_before
    );
    Ok(())
}

// ── ip_bad_checksum_dropped ─────────────────────────────────────────────────
//
// RFC 791 §3.1: The IP header checksum covers only the header; datagrams with
// invalid header checksums MUST be discarded.
//
// With checksum_validate_ip=true, a corrupted IP header checksum must cause
// the frame to be silently dropped.
#[test]
fn ip_bad_checksum_dropped() -> TestResult {
    let mut pair = setup_tcp_pair()
        .profile(LinkProfile::leased_line_100m())
        .connect();

    let rcv_nxt_before = pair.tcp_b().rcv_nxt();

    let mut frame = make_data_frame(&pair);
    frame[IP_CSUM_BYTE] ^= 0xFF;
    pair.inject_to_b(frame);
    pair.transfer_one();

    let rcv_nxt_after = pair.tcp_b().rcv_nxt();
    assert_ok!(
        rcv_nxt_after == rcv_nxt_before,
        "B accepted segment with bad IP checksum (rcv_nxt advanced {} → {})",
        rcv_nxt_before, rcv_nxt_after
    );
    Ok(())
}

// ── ip_checksum_accepted_when_disabled ───────────────────────────────────────
//
// RFC 791 §3.1: IP header checksum validation is mandatory per the spec, but
// our stack exposes a config knob to disable it (e.g. for hardware offload).
//
// With checksum_validate_ip=false, a corrupted IP checksum must still be accepted.
#[test]
fn ip_checksum_accepted_when_disabled() -> TestResult {
    let mut pair = setup_tcp_pair()
        .net_config(NetworkConfig::default)
        .profile(LinkProfile::leased_line_100m())
        .connect();

    let rcv_nxt_before = pair.tcp_b().rcv_nxt();

    let mut frame = make_data_frame(&pair);
    frame[IP_CSUM_BYTE] ^= 0xFF;
    pair.inject_to_b(frame);
    pair.transfer_one();

    let rcv_nxt_after = pair.tcp_b().rcv_nxt();
    let advanced = rcv_nxt_after.wrapping_sub(rcv_nxt_before) < 0x8000_0000;
    assert_ok!(
        advanced && rcv_nxt_after != rcv_nxt_before,
        "B dropped segment with bad IP checksum despite validation being disabled \
         (rcv_nxt stayed at {})",
        rcv_nxt_before
    );
    Ok(())
}

// ── udp_bad_checksum_dropped ────────────────────────────────────────────────
//
// RFC 1122 §4.1.3.4: "A UDP datagram received with an invalid checksum
// MUST be silently discarded."  (RFC 768 defines the checksum but does
// not specify discard behavior.)
//
// With checksum_validate_udp=true, a corrupted UDP checksum must cause
// the frame to be silently dropped (no ICMP Port Unreachable reply).
#[test]
fn udp_bad_checksum_dropped() -> TestResult {
    let mut np = setup_network_pair()
        .profile(LinkProfile::leased_line_100m());

    let mut frame = build_udp_data(
        np.mac_a, np.mac_b,
        np.ip_a,  np.ip_b,
        12345, 9999,
        b"bad-udp-cksum",
    );
    frame[UDP_CSUM_BYTE] ^= 0xFF;

    np.inject_to_b(frame);
    np.transfer_one();

    // No ICMP reply should be generated for a frame with bad checksum.
    let cap = np.drain_captured();
    let icmp_sent = cap.raw().any(|f| {
        f.raw.len() > 37 && f.raw[12] == 0x08 && f.raw[13] == 0x00 && f.raw[23] == 1
    });
    assert_ok!(!icmp_sent, "ICMP sent for UDP frame with bad checksum — should be silently dropped");

    Ok(())
}

// ── udp_checksum_accepted_when_disabled ──────────────────────────────────────
//
// RFC 768: UDP checksum validation is mandatory per the spec, but our stack
// exposes a config knob to disable it (e.g. for hardware offload paths).
//
// With checksum_validate_udp=false, a corrupted UDP checksum must still be
// processed (ICMP Port Unreachable sent for closed port).
#[test]
fn udp_checksum_accepted_when_disabled() -> TestResult {
    let mut np = setup_network_pair()
        .net_config(NetworkConfig::default)
        .profile(LinkProfile::leased_line_100m());

    let mut frame = build_udp_data(
        np.mac_a, np.mac_b,
        np.ip_a,  np.ip_b,
        12345, 9999,
        b"bad-udp-cksum",
    );
    frame[UDP_CSUM_BYTE] ^= 0xFF;

    np.inject_to_b(frame);
    np.transfer_one();

    // With validation disabled, the frame should be accepted and trigger
    // ICMP Port Unreachable (port 9999 is closed).
    let cap = np.drain_captured();
    let icmp_sent = cap.raw().any(|f| {
        f.raw.len() > 37 && f.raw[12] == 0x08 && f.raw[13] == 0x00 && f.raw[23] == 1
    });
    assert_ok!(icmp_sent,
        "no ICMP sent for UDP frame with bad checksum when validation disabled — frame was dropped");

    Ok(())
}

// ── udp_zero_checksum_accepted ──────────────────────────────────────────────
//
// RFC 768: UDP checksum 0x0000 means "no checksum computed" and MUST be
// accepted even when checksum validation is enabled.
#[test]
fn udp_zero_checksum_accepted() -> TestResult {
    let mut np = setup_network_pair()
        .profile(LinkProfile::leased_line_100m());

    let mut frame = build_udp_data(
        np.mac_a, np.mac_b,
        np.ip_a,  np.ip_b,
        12345, 9999,
        b"zero-cksum",
    );
    // Set UDP checksum to 0x0000 (no checksum).
    frame[UDP_CSUM_BYTE] = 0;
    frame[UDP_CSUM_BYTE + 1] = 0;

    np.inject_to_b(frame);
    np.transfer_one();

    // Port 9999 is closed, so the frame should be accepted and trigger
    // ICMP Port Unreachable — proving it was NOT dropped by checksum validation.
    let cap = np.drain_captured();
    let icmp_sent = cap.raw().any(|f| {
        f.raw.len() > 37 && f.raw[12] == 0x08 && f.raw[13] == 0x00 && f.raw[23] == 1
    });
    assert_ok!(
        icmp_sent,
        "UDP frame with checksum 0x0000 was dropped — RFC 768 requires acceptance"
    );

    Ok(())
}
