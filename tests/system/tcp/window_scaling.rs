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

// RFC 7323 §2.2 (WS Negotiation): When client SYN has no WS option, server
// must still establish the connection with scale factors of 0.
#[test]
fn negotiation_one_omits() -> TestResult {
    use rawket::bridge::LinkProfile;
    let mut np = setup_network_pair()
        .profile(LinkProfile::leased_line_100m());
    let cfg = TcpConfig::default();

    let server = TcpSocket::accept(
        np.iface_b(),
        "10.0.0.2:80".parse().unwrap(),
        |_| {}, |_| {},
        cfg,
    )?;
    np.add_tcp_b(server);

    let isn_a = 0x2000_0000u32;
    let syn = build_tcp_syn(
        np.mac_a, np.mac_b,
        np.ip_a, np.ip_b,
        12345, 80,
        isn_a, 0,
        0x02,       // SYN
        Some(1460), // MSS
        None,       // no WS
        None,       // no timestamps
        false,      // no SACK
    );
    np.inject_to_b(syn);
    np.transfer_one();

    let cap = np.drain_captured();
    let syn_ack = cap.tcp().from_b()
        .with_tcp_flags(TcpFlags::SYN)
        .with_tcp_flags(TcpFlags::ACK)
        .next()
        .ok_or_else(|| TestFail::new("no SYN-ACK from B"))?;

    let ack = build_tcp_data(
        np.mac_a, np.mac_b,
        np.ip_a, np.ip_b,
        12345, 80,
        isn_a + 1,
        syn_ack.tcp.seq + 1,
        &[],
    );
    np.inject_to_b(ack);
    np.transfer_one();

    assert_ok!(
        syn_ack.tcp.opts.window_scale.is_none(),
        "SYN-ACK has WS option {:?} despite peer SYN omitting it",
        syn_ack.tcp.opts.window_scale
    );
    assert_state(np.tcp_b(0), State::Established, "B state after handshake without peer WS")?;
    assert_ok!(
        np.tcp_b(0).snd_scale() == 0,
        "snd_scale={} — should be 0 when peer omits WS", np.tcp_b(0).snd_scale()
    );
    assert_ok!(
        np.tcp_b(0).rcv_scale() == 0,
        "rcv_scale={} — should be 0 when peer omits WS", np.tcp_b(0).rcv_scale()
    );

    np.clear_capture();
    let data = build_tcp_data(
        np.mac_a, np.mac_b,
        np.ip_a, np.ip_b,
        12345, 80,
        isn_a + 1,
        syn_ack.tcp.seq + 1,
        b"hello",
    );
    np.inject_to_b(data);
    np.transfer_one();

    let cap = np.drain_captured();
    let acked = cap.tcp().from_b()
        .with_tcp_flags(TcpFlags::ACK)
        .next()
        .is_some();
    assert_ok!(acked, "B did not ACK data after handshake without peer WS");

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

// RFC 7323 §2.2 (WS Negotiation): When peer omits WS, snd_scale and
// rcv_scale must be 0; SYN-ACK must not include WS option.
#[test]
fn unscaled_window_when_peer_omits_ws() -> TestResult {
    use rawket::bridge::LinkProfile;
    let mut np = setup_network_pair()
        .profile(LinkProfile::leased_line_100m());
    let cfg = TcpConfig::default();

    let server = TcpSocket::accept(
        np.iface_b(),
        "10.0.0.2:80".parse().unwrap(),
        |_| {}, |_| {},
        cfg,
    )?;
    np.add_tcp_b(server);

    // Inject a SYN without WS option.
    let syn = build_tcp_syn(
        np.mac_a, np.mac_b,
        np.ip_a, np.ip_b,
        12345, 80,
        1000, 0,
        0x02,       // SYN
        Some(1460), // MSS
        None,       // no WS
        None,       // no timestamps
        false,      // no SACK
    );
    np.inject_to_b(syn);
    np.transfer_one();

    let cap = np.drain_captured();

    // RFC 7323 §2.2: SYN-ACK must NOT include WS when peer omitted it.
    let synack = cap.tcp().from_b()
        .with_tcp_flags(TcpFlags::SYN)
        .with_tcp_flags(TcpFlags::ACK)
        .next()
        .ok_or_else(|| TestFail::new("no SYN-ACK captured"))?;
    assert_ok!(
        synack.tcp.opts.window_scale.is_none(),
        "SYN-ACK included WS option ({:?}) when peer didn't offer WS",
        synack.tcp.opts.window_scale
    );

    // Complete handshake.
    let ack = build_tcp_data(
        np.mac_a, np.mac_b,
        np.ip_a, np.ip_b,
        12345, 80,
        1001,
        synack.tcp.seq + 1,
        b"",
    );
    np.inject_to_b(ack);
    np.transfer_one();

    // Verify B's snd_scale and rcv_scale are 0.
    let sock_b = np.tcp_b(0);
    assert_ok!(
        sock_b.snd_scale() == 0,
        "snd_scale = {} — should be 0 when peer omits WS", sock_b.snd_scale()
    );
    assert_ok!(
        sock_b.rcv_scale() == 0,
        "rcv_scale = {} — should be 0 when peer omits WS", sock_b.rcv_scale()
    );

    // Trigger B to send an ACK by injecting data.
    np.clear_capture();
    let data = build_tcp_data(
        np.mac_a, np.mac_b,
        np.ip_a, np.ip_b,
        12345, 80,
        1001,
        synack.tcp.seq + 1,
        b"hello",
    );
    np.inject_to_b(data);
    np.transfer_one();

    let cap = np.drain_captured();
    let b_ack = cap.tcp().from_b()
        .with_tcp_flags(TcpFlags::ACK)
        .without_tcp_flags(TcpFlags::SYN)
        .next()
        .ok_or_else(|| TestFail::new("no ACK from B after data"))?;

    assert_ok!(b_ack.tcp.window_raw > 0, "raw window is 0 in unscaled ACK");

    Ok(())
}

// RFC 7323 §2.2: Window Scale option in a non-SYN segment must be ignored.
#[test]
fn window_scale_in_non_syn_ignored() -> TestResult {
    use rawket::bridge::LinkProfile;
    let mut pair = setup_tcp_pair()
        .profile(LinkProfile::leased_line_100m())
        .connect();

    let snd_scale_before = pair.tcp_b().snd_scale();
    let rcv_scale_before = pair.tcp_b().rcv_scale();

    // Inject a data segment from A that carries a bogus WS=10 option.
    let seq_a = pair.tcp_a().snd_nxt();
    let ack_a = pair.tcp_a().rcv_nxt();
    let pkt = build_tcp_data_with_ws(
        pair.mac_a, pair.mac_b,
        pair.ip_a,  pair.ip_b,
        12345, 80,
        seq_a, ack_a,
        10, // bogus WS shift
        b"hello",
    );
    pair.inject_to_b(pkt);
    pair.transfer_one();

    // B must accept the data (ACK it) but ignore the WS option.
    let cap = pair.drain_captured();
    let acked = cap.tcp().from_b().with_tcp_flags(TcpFlags::ACK).next().is_some();
    assert_ok!(acked, "B did not ACK data segment with bogus WS option");

    assert_ok!(
        pair.tcp_b().snd_scale() == snd_scale_before,
        "snd_scale changed from {snd_scale_before} to {} after non-SYN WS",
        pair.tcp_b().snd_scale()
    );
    assert_ok!(
        pair.tcp_b().rcv_scale() == rcv_scale_before,
        "rcv_scale changed from {rcv_scale_before} to {} after non-SYN WS",
        pair.tcp_b().rcv_scale()
    );

    assert_state(pair.tcp_b(), State::Established, "B still Established")?;

    Ok(())
}

// RFC 7323 §3.2: after timestamps are negotiated in the handshake, every
// non-RST segment must carry the Timestamps option.
#[test]
fn timestamps_after_negotiation() -> TestResult {
    use rawket::bridge::LinkProfile;
    let mut pair = setup_tcp_pair()
        .profile(LinkProfile::leased_line_100m())
        .connect();

    pair.tcp_a_mut().send(b"from-A")?;
    pair.transfer();

    pair.tcp_b_mut().send(b"from-B")?;
    pair.transfer();

    let cap = pair.drain_captured();

    // Every non-RST segment from B after the SYN-ACK must carry Timestamps.
    let b_segments: Vec<_> = cap.tcp().from_b()
        .without_tcp_flags(TcpFlags::SYN)
        .without_tcp_flags(TcpFlags::RST)
        .collect();

    assert_ok!(!b_segments.is_empty(), "no non-SYN/non-RST segments from B");

    for seg in &b_segments {
        assert_ok!(
            seg.tcp.opts.timestamps.is_some(),
            "segment seq={} flags={:#04x} missing Timestamps option",
            seg.tcp.seq, seg.tcp.flags.bits()
        );
        let (tsval, _tsecr) = seg.tcp.opts.timestamps.unwrap();
        assert_ok!(tsval > 0, "TSval is 0 in segment seq={}", seg.tcp.seq);
    }

    Ok(())
}
