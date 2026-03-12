use rawket::tcp::{State, TcpConfig, TcpFlags, TcpSocket};
use crate::{
    assert::{assert_window_scale, assert_state, TestFail},
    assert_ok,
    capture::ParsedFrameExt,
    harness::{setup_network_pair, setup_tcp_pair},
    packet::{build_tcp_data, build_tcp_data_with_ws, build_tcp_syn},
    TestResult,
};

// Local WS shift advertised by rawket (LOCAL_WS_SHIFT in tcp.rs).
const LOCAL_WS_SHIFT: u8 = 4;

// RFC 7323 §2.2 (WS Negotiation): Both sides use default TcpConfig.  SYN and
// SYN-ACK must each carry WS=LOCAL_WS_SHIFT.
#[test]
fn negotiation_both_sides() -> TestResult {
    use rawket::bridge::LinkProfile;
    let (_pair, cap) = setup_tcp_pair()
        .profile(LinkProfile::leased_line_100m())
        .connect_and_capture();

    let syn = cap.tcp().from_a()
        .with_tcp_flags(TcpFlags::SYN)
        .without_tcp_flags(TcpFlags::ACK)
        .next()
        .ok_or_else(|| TestFail::new("no SYN from A"))?;

    let syn_ack = cap.tcp().from_b()
        .with_tcp_flags(TcpFlags::SYN)
        .with_tcp_flags(TcpFlags::ACK)
        .next()
        .ok_or_else(|| TestFail::new("no SYN-ACK from B"))?;

    assert_window_scale(&syn,     LOCAL_WS_SHIFT, "SYN window scale")?;
    assert_window_scale(&syn_ack, LOCAL_WS_SHIFT, "SYN-ACK window scale")?;

    Ok(())
}
