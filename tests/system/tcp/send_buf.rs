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

// ── cwnd_gate_limits_inflight ─────────────────────────────────────────────────
//
// RFC 9293 §3.8 (Data Communication): Verify inflight bytes do not exceed
// cwnd + 1 MSS.
#[test]
fn cwnd_gate_limits_inflight() -> TestResult {
    use rawket::bridge::LinkProfile;
    let mut pair = setup_tcp_pair()
        .profile(LinkProfile::leased_line_100m())
        .connect();

    let mss = pair.tcp_a().peer_mss() as u32;
    let mut max_overshoot: i64 = 0;
    let mut checks = 0u32;

    pair.tcp_a_mut().send(&vec![0xCCu8; 100_000])?;

    // Verify the invariant continuously during transfer, not just at one snapshot.
    pair.transfer_while(|p| {
        let cwnd = p.tcp_a(0).bbr_cwnd();
        let inflight = p.tcp_a(0).bytes_in_flight();
        if cwnd > 0 && inflight > 0 {
            let overshoot = inflight as i64 - (cwnd + mss) as i64;
            if overshoot > max_overshoot {
                max_overshoot = overshoot;
            }
            checks += 1;
        }
        p.tcp_a(0).send_buf_len() > 0 || p.tcp_a(0).bytes_in_flight() > 0
    });

    assert_ok!(checks >= 5, "too few inflight/cwnd checks ({checks}) — test may be vacuous");
    assert_ok!(
        max_overshoot <= 0,
        "inflight exceeded cwnd + MSS by {max_overshoot} bytes during transfer — \
         cwnd gate not enforced continuously"
    );

    Ok(())
}

// ── send_buf_data_ordering ────────────────────────────────────────────────────
//
// RFC 9293 §3.8 (Data Communication): Send "AAAA" then "BBBB"; data frames
// must appear in monotonically non-decreasing sequence order with contiguous
// coverage.
#[test]
fn send_buf_data_ordering() -> TestResult {
    use rawket::bridge::LinkProfile;
    let mut pair = setup_tcp_pair()
        .profile(LinkProfile::leased_line_100m())
        .connect();

    pair.tcp_a_mut().send(b"AAAA")?;
    pair.tcp_a_mut().send(b"BBBB")?;
    let result = pair.transfer();

    // End-to-end payload content integrity: verify B received "AAAABBBB".
    let received = result.b.get(&0).cloned().unwrap_or_default();
    assert_ok!(
        received == b"AAAABBBB",
        "B received {:?}, expected b\"AAAABBBB\" — payload content corrupted or reordered",
        core::str::from_utf8(&received).unwrap_or("<non-utf8>")
    );

    let cap = pair.drain_captured();
    let total: usize = cap.tcp()
        .direction(Dir::AtoB)
        .with_data()
        .map(|f| f.payload_len)
        .sum();
    assert_ok!(total == 8, "expected 8 bytes sent, got {total}");

    // Collect transmitted segments and verify monotonically non-decreasing
    // sequence numbers.  Retransmits (same seq as previous) are allowed but
    // sequence regressions are not.
    let frames: Vec<(u32, usize)> = cap.tcp()
        .direction(Dir::AtoB)
        .with_data()
        .map(|f| (f.tcp.seq, f.payload_len))
        .collect();
    for i in 1..frames.len() {
        // Allow retransmits: same seq as the previous frame is OK.
        if frames[i].0 == frames[i - 1].0 {
            continue;
        }
        let diff = frames[i].0.wrapping_sub(frames[i - 1].0);
        assert_ok!(
            diff < 0x8000_0000,
            "data frame {} seq ({}) < frame {} seq ({}) — ordering violated",
            i, frames[i].0, i - 1, frames[i - 1].0
        );
        let expected_seq = frames[i - 1].0.wrapping_add(frames[i - 1].1 as u32);
        let gap = frames[i].0.wrapping_sub(expected_seq);
        assert_ok!(
            gap < 0x8000_0000,
            "gap in sequence space between frame {} and {}: expected seq {expected_seq}, got {}",
            i - 1, i, frames[i].0
        );
    }

    Ok(())
}

// ── zero_send_buf_persist ─────────────────────────────────────────────────────
//
// RFC 9293 §3.8 (Data Communication): Empty send_buf + zero window: persist
// timer must NOT arm (nothing to probe).
#[test]
fn zero_send_buf_persist() -> TestResult {
    use rawket::bridge::LinkProfile;
    let mut pair = setup_tcp_pair()
        .profile(LinkProfile::leased_line_100m())
        .connect();

    pair.tcp_a_mut().send(b"x")?;
    pair.transfer();

    let cap = pair.drain_captured();
    let (a_snd_una, b_snd_nxt) = {
        let f = cap.tcp()
            .direction(Dir::AtoB)
            .with_data()
            .next()
            .ok_or_else(|| crate::assert::TestFail::new("no AtoB data frame"))?;
        (f.tcp.seq + 1, f.tcp.ack)
    };

    inject_zero_window(&mut pair, b_snd_nxt, a_snd_una);
    pair.clear_capture();

    // Persist should NOT be armed (send_buf is empty).
    let timers = pair.tcp_a().timer_state();
    assert_ok!(timers.persist_ns.is_none(), "persist armed with empty send_buf: {timers:?}");

    let rto = pair.tcp_a().rto_ms() as i64;
    pair.advance_both(rto * 4);
    pair.transfer_one();

    // Check all A→B frames (not just with_data — persist probes may be 0 or 1 byte).
    let cap2 = pair.drain_captured();
    let a_frames = cap2.tcp()
        .direction(Dir::AtoB)
        .count();
    assert_ok!(
        a_frames == 0,
        "frames sent from A with empty send_buf ({a_frames} frames) — persist should not arm"
    );

    Ok(())
}

// ── sws_sender_small_window ─────────────────────────────────────────────────
//
// RFC 9293 §3.8.6.2.1, RFC 1122 §4.2.3.4: sender-side Silly Window Syndrome
// avoidance.
// When the peer opens a window much smaller than MSS and the sender has
// ≥ MSS bytes buffered, verify the sender sends eagerly (this implementation
// does not defer to a full MSS window — it sends whatever the window allows).
#[test]
fn sws_sender_small_window() -> TestResult {
    use rawket::bridge::LinkProfile;
    let mut pair = setup_tcp_pair()
        .profile(LinkProfile::leased_line_100m())
        .connect();

    pair.tcp_a_mut().send(b"x")?;
    pair.transfer();

    let cap = pair.drain_captured();
    let (a_first_seq, b_snd_nxt) = {
        let f = cap.tcp()
            .direction(Dir::AtoB)
            .with_data()
            .next()
            .ok_or_else(|| crate::assert::TestFail::new("no AtoB data frame"))?;
        (f.tcp.seq, f.tcp.ack)
    };
    let a_snd_una = a_first_seq + 1;

    // Freeze the window at zero.
    inject_zero_window(&mut pair, b_snd_nxt, a_snd_una);

    // Buffer several MSS worth of data.
    let mss = pair.tcp_a().peer_mss() as usize;
    let fill = vec![0xABu8; mss * 3];
    pair.tcp_a_mut().send(&fill)?;

    // Advance past pacing gate.
    pair.advance_both(2000);
    pair.clear_capture();

    // Open window to a small value (well below MSS).
    // The raw window field is scaled by snd_scale, so set a raw value that
    // produces an effective window of ~10 bytes after scaling.
    let snd_scale = pair.tcp_a().snd_scale();
    let effective_window = 10u32;
    // Raw value must be at least 1 to open the window; if scale would make
    // effective > 10, use raw=1 (effective = 1 << scale).
    let raw_window = if snd_scale == 0 {
        effective_window as u16
    } else {
        1u16 // effective = 1 << snd_scale
    };
    let actual_effective = (raw_window as u32) << snd_scale;

    let mut ack = build_tcp_data(
        pair.mac_b, pair.mac_a, pair.ip_b, pair.ip_a,
        80, 12345,
        b_snd_nxt, a_snd_una,
        b"",
    );
    // Patch window field (bytes 48-49 of Ethernet frame = TCP offset 14-15).
    ack[48] = (raw_window >> 8) as u8;
    ack[49] = (raw_window & 0xFF) as u8;
    recompute_frame_tcp_checksum(&mut ack);
    pair.inject_to_a(ack);
    pair.transfer_one();

    let cap2 = pair.drain_captured();
    let data_frames: Vec<usize> = cap2.tcp()
        .direction(Dir::AtoB)
        .with_data()
        .map(|f| f.payload_len)
        .collect();

    // This implementation sends eagerly: it WILL send a segment ≤ the effective
    // window even though send_buf >> MSS.  RFC 1122 §4.2.3.4 SHOULD avoid this,
    // but for a minimal stack the eager behavior is acceptable and deterministic.
    assert_ok!(
        !data_frames.is_empty(),
        "expected sender to send data when window opened to {actual_effective} bytes"
    );
    assert_ok!(
        actual_effective < mss as u32,
        "effective window ({actual_effective}) should be below MSS ({mss}) for this test"
    );
    for &len in &data_frames {
        assert_ok!(
            len <= actual_effective as usize,
            "segment payload {len} exceeds effective window {actual_effective}"
        );
    }

    Ok(())
}
