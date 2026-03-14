#![allow(dead_code, unused_imports)]
use rawket::tcp::{State, TcpError, TcpFlags, TcpSocket};
use rawket::bridge::{Impairment, PacketSpec};
use rawket::filter;
use std::net::Ipv4Addr;
use crate::{
    TestResult, assert_ok,
    assert::{assert_ack, assert_error_fired, assert_flags, assert_flags_exact, assert_state},
    capture::{Dir, ParsedFrameExt},
    harness::{fast_tcp_cfg, setup_network_pair, setup_tcp_pair},
    packet::{build_tcp_data, build_tcp_data_with_flags, build_tcp_rst, build_tcp_syn,
             build_udp_data},
};

// RFC 9293 §3.5 (Connection Establishment): Three-way handshake SYN, SYN-ACK, ACK.
#[test]
fn basic_handshake() -> TestResult {
    use rawket::bridge::LinkProfile;
    let (pair, cap) = setup_tcp_pair()
        .profile(LinkProfile::leased_line_100m())
        .connect_and_capture();

    let all_frames: Vec<_> = cap.all_tcp().collect();

    // Initial SYN: SYN set, ACK not set.
    let syn_frames: Vec<_> = all_frames.iter()
        .filter(|f| f.tcp.flags.has(TcpFlags::SYN) && !f.tcp.flags.has(TcpFlags::ACK))
        .collect();
    assert_ok!(syn_frames.len() == 1, "expected exactly 1 SYN, got {} (total frames: {})", syn_frames.len(), all_frames.len());

    // SYN-ACK: both SYN and ACK set.
    let synack_frames: Vec<_> = all_frames.iter()
        .filter(|f| f.tcp.flags.has(TcpFlags::SYN) && f.tcp.flags.has(TcpFlags::ACK))
        .collect();
    assert_ok!(synack_frames.len() == 1, "expected exactly 1 SYN-ACK, got {}", synack_frames.len());

    // Final ACK: ACK set, SYN not set.
    let ack_frames: Vec<_> = all_frames.iter()
        .filter(|f| f.tcp.flags.has(TcpFlags::ACK) && !f.tcp.flags.has(TcpFlags::SYN))
        .collect();
    assert_ok!(!ack_frames.is_empty(), "no ACK frame captured");

    let syn    = syn_frames[0];
    let synack = synack_frames[0];
    let ack    = ack_frames[0];

    // Exact flag verification: SYN carries ECE|CWR for ECN negotiation (RFC 3168 §6.1.1).
    assert_flags_exact(syn, TcpFlags::SYN | TcpFlags::ECE | TcpFlags::CWR, "SYN flags")?;
    // SYN-ACK echoes ECE to confirm ECN support (RFC 3168 §6.1.1).
    assert_flags_exact(synack, TcpFlags::SYN | TcpFlags::ACK | TcpFlags::ECE, "SYN-ACK flags")?;
    assert_flags_exact(ack, TcpFlags::ACK, "final ACK flags")?;

    assert_ack(synack, syn.tcp.seq.wrapping_add(1), "SYN-ACK acks client ISN")?;
    assert_ack(ack,    synack.tcp.seq.wrapping_add(1), "ACK acks server ISN")?;

    // Direction: SYN from A, SYN-ACK from B, ACK from A.
    assert_ok!(syn.dir == Dir::AtoB, "SYN should be from A, got {:?}", syn.dir);
    assert_ok!(synack.dir == Dir::BtoA, "SYN-ACK should be from B, got {:?}", synack.dir);
    assert_ok!(ack.dir == Dir::AtoB, "third ACK should be from A, got {:?}", ack.dir);

    // SYN and SYN-ACK must carry no payload.
    assert_ok!(syn.payload_len == 0, "SYN has payload ({} bytes)", syn.payload_len);
    assert_ok!(synack.payload_len == 0, "SYN-ACK has payload ({} bytes)", synack.payload_len);

    // SYN must carry MSS option (RFC 9293 §3.7.1).
    assert_ok!(
        syn.tcp.opts.mss.is_some(),
        "SYN missing MSS option"
    );
    assert_ok!(
        synack.tcp.opts.mss.is_some(),
        "SYN-ACK missing MSS option"
    );

    // Both SYN and SYN-ACK must advertise a non-zero window.
    assert_ok!(syn.tcp.window_raw > 0, "SYN window is 0");
    assert_ok!(synack.tcp.window_raw > 0, "SYN-ACK window is 0");

    assert_state(pair.tcp_a(), State::Established, "client")?;
    assert_state(pair.tcp_b(), State::Established, "server")?;

    Ok(())
}
