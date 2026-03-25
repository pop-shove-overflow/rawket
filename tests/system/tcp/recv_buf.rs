use rawket::tcp::TcpFlags;
use crate::{
    assert_ok,
    capture::{Dir, ParsedFrameExt},
    harness::setup_tcp_pair,
    packet::build_tcp_data_with_ts,
    TestResult,
};

// ── recv_buf_exhaustion_drops_segment ────────────────────────────────────────
//
// RFC 9293 §3.8: When the receive buffer is full and the application has not
// consumed data, in-window segments must be dropped (not delivered).
// rcv_nxt must not advance.
#[test]
fn recv_buf_exhaustion_drops_segment() -> TestResult {
    use rawket::bridge::LinkProfile;
    let mut pair = setup_tcp_pair()
        .recv_buf_max(100)
        .profile(LinkProfile::leased_line_100m())
        .connect();

    let rcv_nxt = pair.tcp_b().rcv_nxt();
    let b_snd_nxt = pair.tcp_b().snd_nxt();

    // Fill B's recv_buf by injecting exactly 100 bytes directly.
    // transfer_one() polls but does NOT drain recv_buf (no sock.recv() call).
    let fill = build_tcp_data_with_ts(
        pair.mac_a, pair.mac_b,
        pair.ip_a,  pair.ip_b,
        12345, 80,
        rcv_nxt,
        b_snd_nxt,
        0, 0, // timestamps patched by inject_to_b
        &vec![0xAAu8; 100],
    );
    pair.inject_to_b(fill);
    pair.transfer_one();

    let rcv_nxt_after_fill = pair.tcp_b().rcv_nxt();
    assert_ok!(
        rcv_nxt_after_fill == rcv_nxt + 100,
        "fill segment not accepted: rcv_nxt {} → {} (expected +100)",
        rcv_nxt, rcv_nxt_after_fill
    );

    // Now inject more in-window data — recv_buf is full, must be dropped.
    let extra = build_tcp_data_with_ts(
        pair.mac_a, pair.mac_b,
        pair.ip_a,  pair.ip_b,
        12345, 80,
        rcv_nxt_after_fill,
        b_snd_nxt,
        0, 0,
        b"overflow-data",
    );
    pair.inject_to_b(extra);
    pair.transfer_one();

    // rcv_nxt must NOT advance — segment was dropped due to full recv_buf.
    let rcv_nxt_final = pair.tcp_b().rcv_nxt();
    assert_ok!(
        rcv_nxt_final == rcv_nxt_after_fill,
        "rcv_nxt advanced ({rcv_nxt_after_fill} → {rcv_nxt_final}) despite full recv_buf"
    );

    // B must send an ACK for the rejected segment with window=0 and ack=rcv_nxt.
    let cap = pair.drain_captured();
    let ack = cap.tcp()
        .direction(Dir::BtoA)
        .with_tcp_flags(TcpFlags::ACK)
        .last()
        .ok_or_else(|| crate::assert::TestFail::new(
            "B did not send ACK for rejected segment — expected ACK with window=0"
        ))?;
    assert_ok!(
        ack.tcp.ack == rcv_nxt_after_fill,
        "B's ACK ({}) != rcv_nxt ({rcv_nxt_after_fill}) — should be duplicate ACK", ack.tcp.ack
    );
    assert_ok!(
        ack.tcp.window_raw == 0,
        "B advertised window {} after recv_buf full — expected 0", ack.tcp.window_raw
    );

    Ok(())
}

// ── recv_partial_read_and_drain ─────────────────────────────────────────────
//
// Verify the recv() API: partial reads, drain-on-read, and None when empty.
#[test]
fn recv_partial_read_and_drain() -> TestResult {
    use rawket::bridge::LinkProfile;
    let mut pair = setup_tcp_pair()
        .recv_buf_max(1024)
        .profile(LinkProfile::leased_line_100m())
        .connect();

    let rcv_nxt = pair.tcp_b().rcv_nxt();
    let b_snd_nxt = pair.tcp_b().snd_nxt();

    // Inject 10 bytes into B's recv_buf (don't drain via transfer).
    let data = build_tcp_data_with_ts(
        pair.mac_a, pair.mac_b,
        pair.ip_a,  pair.ip_b,
        12345, 80,
        rcv_nxt, b_snd_nxt,
        0, 0,
        b"0123456789",
    );
    pair.inject_to_b(data);
    pair.transfer_one(); // processes into recv_buf, does NOT drain

    // Partial read: 4-byte buffer reads first 4 bytes.
    let mut buf = [0u8; 4];
    let n = pair.tcp_b_mut().recv(&mut buf);
    assert_ok!(n == Some(4), "partial recv returned {:?}, expected Some(4)", n);
    assert_ok!(&buf == b"0123", "partial recv content: {:?}", buf);

    // Second read: remaining 6 bytes, but buffer is 4 → reads 4.
    let n = pair.tcp_b_mut().recv(&mut buf);
    assert_ok!(n == Some(4), "second recv returned {:?}, expected Some(4)", n);
    assert_ok!(&buf == b"4567", "second recv content: {:?}", buf);

    // Third read: 2 bytes remaining.
    let n = pair.tcp_b_mut().recv(&mut buf);
    assert_ok!(n == Some(2), "third recv returned {:?}, expected Some(2)", n);
    assert_ok!(&buf[..2] == b"89", "third recv content: {:?}", &buf[..2]);

    // Fourth read: empty → None.
    let n = pair.tcp_b_mut().recv(&mut buf);
    assert_ok!(n.is_none(), "recv on empty buf returned {:?}, expected None", n);

    Ok(())
}
