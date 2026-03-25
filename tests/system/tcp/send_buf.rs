use rawket::tcp::TcpFlags;
use crate::{
    assert::assert_would_block,
    assert_ok,
    capture::{Dir, ParsedFrameExt},
    harness::setup_tcp_pair,
    packet::{build_tcp_data, recompute_frame_tcp_checksum},
    TestResult,
};

/// Build a zero-window ACK from B→A. seq=b_snd_nxt, ack=a_snd_una, window=0.
fn inject_zero_window(
    pair: &mut crate::harness::TcpSocketPair,
    b_snd_nxt: u32,
    a_snd_una: u32,
) {
    let mut zw = build_tcp_data(
        pair.mac_b, pair.mac_a, pair.ip_b, pair.ip_a,
        80, 12345,
        b_snd_nxt,
        a_snd_una,
        b"",
    );
    zw[48] = 0; zw[49] = 0; // zero window (raw unscaled)
    recompute_frame_tcp_checksum(&mut zw);
    pair.inject_to_a(zw);
    pair.transfer_one();
}

/// Build an open-window ACK from B→A (window = 65535).
fn inject_open_window(
    pair: &mut crate::harness::TcpSocketPair,
    b_snd_nxt: u32,
    a_snd_una: u32,
) {
    let frame = build_tcp_data(
        pair.mac_b, pair.mac_a, pair.ip_b, pair.ip_a,
        80, 12345,
        b_snd_nxt,
        a_snd_una,
        b"",
    );
    pair.inject_to_a(frame);
    pair.transfer_one();
}

// ── backpressure_would_block ──────────────────────────────────────────────────
//
// RFC 9293 §3.8 (Data Communication): Fill send buffer to 1 MiB under
// zero-window; the next send must return WouldBlock.
#[test]
fn backpressure_would_block() -> TestResult {
    use rawket::bridge::LinkProfile;
    let mut pair = setup_tcp_pair()
        .profile(LinkProfile::leased_line_100m())
        .connect();

    pair.tcp_a_mut().send(b"x")?;
    pair.transfer();

    let cap = pair.drain_captured();
    let (a_data_seq, b_snd_nxt) = {
        let f = cap.tcp()
            .direction(Dir::AtoB)
            .with_data()
            .next()
            .ok_or_else(|| crate::assert::TestFail::new("no AtoB data frame"))?;
        (f.tcp.seq, f.tcp.ack)
    };

    // Inject zero-window ACK (acks the "x" byte: seq + 1).
    inject_zero_window(&mut pair, b_snd_nxt, a_data_seq + 1);

    // Prove the zero-window ACK was accepted before testing backpressure.
    assert_ok!(
        pair.tcp_a().snd_wnd() == 0,
        "snd_wnd not zero after zero-window inject: {}", pair.tcp_a().snd_wnd()
    );

    // Fill send buffer to exactly send_buf_max.
    let fill = vec![0u8; pair.tcp_cfg.send_buf_max];
    pair.tcp_a_mut().send(&fill)?;

    // One more byte must fail with WouldBlock.
    let result = pair.tcp_a_mut().send(b"y");
    assert_would_block(result, "send past send_buf_max")?;

    Ok(())
}

// ── flow_control_window ───────────────────────────────────────────────────────
//
// RFC 9293 §3.7.2 (SWS Avoidance): After zero-window, buffered data stays.
// Opening the window flushes it.
#[test]
fn flow_control_window() -> TestResult {
    use rawket::bridge::LinkProfile;
    let mut pair = setup_tcp_pair()
        .profile(LinkProfile::leased_line_100m())
        .connect();

    pair.tcp_a_mut().send(b"hello")?;
    pair.transfer();

    let cap = pair.drain_captured();
    let (a_snd_una_after_hello, b_snd_nxt) = {
        let f = cap.tcp()
            .direction(Dir::AtoB)
            .with_data()
            .next()
            .ok_or_else(|| crate::assert::TestFail::new("no AtoB data frame"))?;
        (f.tcp.seq, f.tcp.ack)
    };
    let a_snd_una = a_snd_una_after_hello + 5;

    inject_zero_window(&mut pair, b_snd_nxt, a_snd_una);
    assert_ok!(
        pair.tcp_a().snd_wnd() == 0,
        "snd_wnd not zero after zero-window inject: {}", pair.tcp_a().snd_wnd()
    );

    pair.tcp_a_mut().send(b"world")?;

    pair.clear_capture();
    pair.transfer_one();

    let cap1 = pair.drain_captured();
    let data_after_zw = cap1.tcp()
        .direction(Dir::AtoB)
        .with_data()
        .count();
    assert_ok!(data_after_zw == 0, "A sent data while window was zero ({data_after_zw} frames)");

    // Advance to expire pacing gate.
    pair.advance_both(2000);

    inject_open_window(&mut pair, b_snd_nxt, a_snd_una);
    pair.transfer_one();

    let cap2 = pair.drain_captured();
    let data_after_open = cap2.tcp()
        .direction(Dir::AtoB)
        .with_data()
        .count();
    assert_ok!(data_after_open >= 1, "A did not send buffered 'world' after window opened");

    // Verify all 5 bytes of "world" were transmitted.
    let total_bytes: usize = cap2.tcp()
        .direction(Dir::AtoB)
        .with_data()
        .map(|f| f.payload_len)
        .sum();
    assert_ok!(
        total_bytes >= 5,
        "expected all 5 bytes of 'world' sent after window opened, got {total_bytes}"
    );

    Ok(())
}
