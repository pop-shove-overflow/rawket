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

// RFC 7323 §2.3 (Window Calculation): With WS=4, effective window is far
// larger than 65535.  Send 65536 bytes to exercise scaled window.
#[test]
fn large_window_transfer() -> TestResult {
    use rawket::bridge::LinkProfile;
    let mut pair = setup_tcp_pair()
        .profile(LinkProfile::leased_line_100m())
        .connect();

    let big = vec![0x55u8; 65_536];
    pair.tcp_a_mut().send(&big)?;

    // Drive until B ACKs all data.
    pair.transfer();

    let cap = pair.drain_captured();
    let total: usize = cap.tcp().from_a().with_data().map(|f| f.payload_len).sum();
    assert_ok!(total == 65_536, "expected 65536 bytes from A but got {total}");

    // Prove window scaling was active and required: B's advertised window
    // (reconstructed with scale) must have exceeded 65535 at some point.
    let rcv_scale = pair.tcp_b().rcv_scale();
    assert_ok!(rcv_scale > 0, "rcv_scale is 0 — no window scaling negotiated");

    let max_effective_wnd: u32 = cap.tcp().from_b()
        .map(|f| (f.tcp.window_raw as u32) << rcv_scale)
        .max()
        .unwrap_or(0);
    assert_ok!(
        max_effective_wnd > 65535,
        "max effective window ({max_effective_wnd}) <= 65535 — scaling not required for this transfer"
    );

    assert_ok!(
        pair.tcp_a().state == rawket::tcp::State::Established,
        "A not Established after large transfer"
    );

    Ok(())
}

// RFC 7323 §2.3 (Window Calculation): After handshake with WS=4, B's window
// advertisement must represent the scaled window.
#[test]
fn receive_window_advertisement() -> TestResult {
    use rawket::bridge::LinkProfile;
    let mut pair = setup_tcp_pair()
        .profile(LinkProfile::leased_line_100m())
        .connect();

    pair.tcp_a_mut().send(b"hello")?;
    pair.transfer();

    let cap = pair.drain_captured();
    let b_ack = cap.tcp().from_b()
        .with_tcp_flags(TcpFlags::ACK)
        .without_tcp_flags(TcpFlags::SYN)
        .last()
        .ok_or_else(|| TestFail::new("no data ACK from B"))?;

    // B's rcv_scale must equal LOCAL_WS_SHIFT (both sides use default config).
    assert_ok!(
        pair.tcp_b().rcv_scale() == LOCAL_WS_SHIFT,
        "rcv_scale={} — expected {LOCAL_WS_SHIFT}", pair.tcp_b().rcv_scale()
    );

    let raw_window = b_ack.tcp.window_raw;
    let scaled_window = (raw_window as u32) << LOCAL_WS_SHIFT;

    assert_ok!(raw_window > 0, "B's raw window in ACK is 0");
    assert_ok!(
        scaled_window > 65535,
        "scaled window ({scaled_window}) ≤ 65535 — window scaling may not be active"
    );
    assert_ok!(
        scaled_window <= 1_048_576,
        "B's scaled window ({scaled_window}) exceeds recv_buf_max (1048576)"
    );

    Ok(())
}
