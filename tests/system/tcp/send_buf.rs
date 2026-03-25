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
