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

// ── send_buf_drains_as_acked ──────────────────────────────────────────────────
//
// RFC 9293 §3.8 (Data Communication): After B ACKs 100 bytes, a subsequent
// 100-byte send must succeed.
#[test]
fn send_buf_drains_as_acked() -> TestResult {
    use rawket::bridge::LinkProfile;
    let mut pair = setup_tcp_pair()
        .profile(LinkProfile::leased_line_100m())
        .connect();

    let data = vec![0u8; 100];
    pair.tcp_a_mut().send(&data)?;
    pair.transfer();

    pair.tcp_a_mut().send(&data)?;
    pair.transfer();

    let cap = pair.drain_captured();
    let total_bytes: usize = cap.tcp()
        .direction(Dir::AtoB)
        .map(|f| f.payload_len)
        .sum();
    assert_ok!(total_bytes >= 200, "expected ≥200 bytes from A, got {total_bytes}");

    // Buffer must be fully drained after ACKs.
    let buf_len = pair.tcp_a().send_buf_len();
    assert_ok!(buf_len == 0, "send_buf not drained after ACKs: {buf_len} bytes remaining");

    Ok(())
}

// ── flow_control_window_grows ─────────────────────────────────────────────────
//
// RFC 9293 §3.8 (Data Communication): During a 30 KB bulk transfer, B's
// advertised window should always be > 0 and all data delivered.
#[test]
fn flow_control_window_grows() -> TestResult {
    use rawket::bridge::LinkProfile;
    let mut pair = setup_tcp_pair()
        .profile(LinkProfile::leased_line_100m())
        .connect();

    let data = vec![0xABu8; 30_000];
    pair.tcp_a_mut().send(&data)?;
    pair.transfer();

    let cap = pair.drain_captured();
    let windows: Vec<u16> = cap.tcp()
        .direction(Dir::BtoA)
        .with_tcp_flags(TcpFlags::ACK)
        .without_tcp_flags(TcpFlags::SYN)
        .map(|f| f.tcp.window_raw)
        .collect();
    assert_ok!(!windows.is_empty(), "no ACKs from B");

    let all_nonzero = windows.iter().all(|&w| w > 0);
    assert_ok!(
        all_nonzero,
        "B advertised zero window during transfer — windows: {:?}", &windows[..windows.len().min(10)]
    );

    // Window should show growth: max > min (receiver opens window as data is consumed).
    let min_w = *windows.iter().min().unwrap();
    let max_w = *windows.iter().max().unwrap();
    assert_ok!(
        max_w > min_w,
        "window did not grow during transfer — all values equal ({min_w})"
    );

    let total: usize = cap.tcp()
        .direction(Dir::AtoB)
        .with_data()
        .map(|f| f.payload_len)
        .sum();
    assert_ok!(
        total == 30_000,
        "expected 30000 bytes delivered, got {total}"
    );

    // Send buffer should be fully drained.
    let buf_len = pair.tcp_a().send_buf_len();
    assert_ok!(buf_len == 0, "send_buf not fully drained: {buf_len} bytes remaining");

    // Verify A's effective (scaled) send window is non-zero and > MSS.
    // The raw window check above only proves the 16-bit field is non-zero;
    // this proves the actual usable window (with scaling applied) is meaningful.
    let snd_wnd = pair.tcp_a().snd_wnd();
    let mss = pair.tcp_a().peer_mss() as u32;
    assert_ok!(
        snd_wnd >= mss,
        "scaled snd_wnd ({snd_wnd}) < MSS ({mss}) after 30KB transfer — \
         window should have grown"
    );

    Ok(())
}
