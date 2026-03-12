// Checksum validation tests.
//
// rawket has per-protocol RX checksum validation flags:
//   - Enabled by `setup_tcp_pair()` → `test_network_config()`
//   - Disabled by `.net_config(NetworkConfig::default)` → `NetworkConfig::default()`
//
// TCP checksum offset:
//   Ethernet(14) + IPv4(20) + TCP_offset(16) = byte 50
//   (same whether or not timestamps are present)

use rawket::{network::NetworkConfig, tcp::State};
use crate::{
    assert::assert_state,
    assert_ok,
    harness::setup_tcp_pair,
    packet::build_tcp_data,
    TestResult,
};

const TCP_CSUM_BYTE: usize = 50;

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
