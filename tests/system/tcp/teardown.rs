use rawket::tcp::{State, TcpError, TcpFlags};
use crate::{
    assert::{assert_error_fired, assert_gap_approx, assert_state, TestFail},
    assert_ok,
    capture::{Dir, ParsedFrameExt},
    harness::setup_tcp_pair,
    packet::{build_tcp_data, build_tcp_data_with_flags, build_tcp_rst, build_tcp_syn},
    TestResult,
};

// ── active_close ───────────────────────────────────────────────────────────────
//
// RFC 9293 §3.6 (Connection Close): Standard four-way FIN handshake,
// client-initiated.
#[test]
fn active_close() -> TestResult {
    use rawket::bridge::LinkProfile;
    let mut pair = setup_tcp_pair()
        .time_wait_ms(100)
        .profile(LinkProfile::leased_line_100m())
        .connect();

    pair.tcp_a_mut().close()?;
    assert_state(pair.tcp_a(), State::FinWait1, "A FinWait1 after close()")?;

    pair.transfer();
    assert_state(pair.tcp_a(), State::FinWait2, "A FinWait2 after B ACKs FIN")?;
    assert_state(pair.tcp_b(), State::CloseWait, "B CloseWait")?;

    pair.tcp_b_mut().close()?;

    pair.transfer_while(|p| {
        p.tcp_a(0).state != State::TimeWait || p.tcp_b(0).state != State::Closed
    });
    assert_state(pair.tcp_a(), State::TimeWait, "A TimeWait")?;
    assert_state(pair.tcp_b(), State::Closed, "B Closed")?;

    pair.transfer();
    assert_state(pair.tcp_a(), State::Closed, "A Closed after TimeWait expiry")?;

    let cap = pair.drain_captured();
    let a_fins = cap.tcp().direction(Dir::AtoB).with_tcp_flags(TcpFlags::FIN).count();
    let b_fins = cap.tcp().direction(Dir::BtoA).with_tcp_flags(TcpFlags::FIN).count();
    assert_ok!(a_fins == 1, "expected exactly 1 FIN from A, got {a_fins}");
    assert_ok!(b_fins == 1, "expected exactly 1 FIN from B, got {b_fins}");

    Ok(())
}

// ── passive_close ──────────────────────────────────────────────────────────────
//
// RFC 9293 §3.6 (Connection Close): Server-initiated close; client performs
// the passive close.
#[test]
fn passive_close() -> TestResult {
    use rawket::bridge::LinkProfile;
    let mut pair = setup_tcp_pair()
        .time_wait_ms(100)
        .profile(LinkProfile::leased_line_100m())
        .connect();

    pair.tcp_b_mut().close()?;
    assert_state(pair.tcp_b(), State::FinWait1, "B FinWait1 after close()")?;

    pair.transfer();
    assert_state(pair.tcp_b(), State::FinWait2, "B FinWait2")?;
    assert_state(pair.tcp_a(), State::CloseWait, "A CloseWait")?;

    pair.tcp_a_mut().close()?;

    pair.transfer_while(|p| {
        p.tcp_b(0).state != State::TimeWait || p.tcp_a(0).state != State::Closed
    });
    assert_state(pair.tcp_b(), State::TimeWait, "B TimeWait")?;
    assert_state(pair.tcp_a(), State::Closed, "A Closed")?;

    pair.transfer();
    assert_state(pair.tcp_b(), State::Closed, "B Closed after TimeWait expiry")?;

    let cap = pair.drain_captured();
    let a_fins = cap.tcp().direction(Dir::AtoB).with_tcp_flags(TcpFlags::FIN).count();
    let b_fins = cap.tcp().direction(Dir::BtoA).with_tcp_flags(TcpFlags::FIN).count();
    assert_ok!(a_fins == 1, "expected exactly 1 FIN from A, got {a_fins}");
    assert_ok!(b_fins == 1, "expected exactly 1 FIN from B, got {b_fins}");

    Ok(())
}

// ── simultaneous_close ─────────────────────────────────────────────────────────
//
// RFC 9293 §3.6 (Connection Close): Both sides call close() before any poll;
// both enter Closing.
#[test]
fn simultaneous_close() -> TestResult {
    use rawket::bridge::LinkProfile;
    let mut pair = setup_tcp_pair()
        .time_wait_ms(100)
        .profile(LinkProfile::leased_line_100m())
        .connect();

    pair.tcp_a_mut().close()?;
    assert_state(pair.tcp_a(), State::FinWait1, "A FinWait1 after close()")?;
    pair.tcp_b_mut().close()?;
    assert_state(pair.tcp_b(), State::FinWait1, "B FinWait1 after close()")?;

    // Both FINs cross in flight; both sides reach TimeWait.
    pair.transfer_while(|p| {
        p.tcp_a(0).state != State::TimeWait || p.tcp_b(0).state != State::TimeWait
    });
    assert_state(pair.tcp_a(), State::TimeWait, "A TimeWait")?;
    assert_state(pair.tcp_b(), State::TimeWait, "B TimeWait")?;

    // TimeWait expires.
    pair.transfer();
    assert_state(pair.tcp_a(), State::Closed, "A Closed")?;
    assert_state(pair.tcp_b(), State::Closed, "B Closed")?;

    let cap = pair.drain_captured();
    let a_fins = cap.tcp().direction(Dir::AtoB).with_tcp_flags(TcpFlags::FIN).count();
    let b_fins = cap.tcp().direction(Dir::BtoA).with_tcp_flags(TcpFlags::FIN).count();
    assert_ok!(a_fins == 1, "expected 1 FIN from A, got {a_fins}");
    assert_ok!(b_fins == 1, "expected 1 FIN from B, got {b_fins}");

    Ok(())
}

// ── rst_abortive_close ─────────────────────────────────────────────────────────
//
// RFC 9293 §3.6 (Connection Close): Server calls abort(): RST sent
// immediately, client observes Closed + Reset.  No FIN should appear.
#[test]
fn rst_abortive_close() -> TestResult {
    use rawket::bridge::LinkProfile;
    let mut pair = setup_tcp_pair()
        .profile(LinkProfile::leased_line_100m())
        .connect();

    let b_snd_nxt = pair.tcp_b().snd_nxt();

    pair.tcp_b_mut().abort()?;
    assert_state(pair.tcp_b(), State::Closed, "B Closed after abort")?;

    pair.transfer();
    assert_state(pair.tcp_a(), State::Closed, "A Closed after RST")?;
    assert_error_fired(pair.tcp_a(), TcpError::Reset, "A error = Reset")?;

    let cap = pair.drain_captured();
    let fins = cap.tcp().with_tcp_flags(TcpFlags::FIN).count();
    assert_ok!(fins == 0, "expected no FIN frames after abort, got {fins}");

    let rst_frames: Vec<_> = cap.tcp()
        .direction(Dir::BtoA)
        .with_tcp_flags(TcpFlags::RST)
        .collect();
    assert_ok!(rst_frames.len() == 1, "expected 1 RST from B, got {}", rst_frames.len());

    let rst_seq = rst_frames[0].tcp.seq;
    assert_ok!(
        rst_seq == b_snd_nxt,
        "RST seq ({rst_seq}) != B's snd_nxt ({b_snd_nxt})"
    );

    Ok(())
}

// ── data_after_fin_ignored ─────────────────────────────────────────────────────
//
// RFC 9293 §3.10.7.4 (Seventh step, CLOSE-WAIT): "This should not occur since
// a FIN has been received from the remote side.  Ignore the segment text."
// After B sends FIN and A enters CloseWait, data at B's FIN seq + 1 passes
// the acceptability test but the segment text is ignored.  A remains in
// CloseWait.
#[test]
fn data_after_fin_ignored() -> TestResult {
    use rawket::bridge::LinkProfile;
    let mut pair = setup_tcp_pair()
        .profile(LinkProfile::leased_line_100m())
        .connect();

    pair.tcp_b_mut().close()?;
    pair.transfer();
    assert_state(pair.tcp_a(), State::CloseWait, "A CloseWait")?;

    // Find B's FIN seq from captures.
    let cap0 = pair.drain_captured();
    let fin_frame = cap0.tcp()
        .direction(Dir::BtoA)
        .with_tcp_flags(TcpFlags::FIN)
        .next()
        .ok_or_else(|| TestFail::new("no BtoA FIN in capture after B.close()"))?;
    let fin_seq = fin_frame.tcp.seq;

    let a_snd_nxt = pair.tcp_a().snd_nxt();
    let rcv_nxt_before = pair.tcp_a().rcv_nxt();
    let data_frame = crate::harness::b_to_a(
        &pair, fin_seq.wrapping_add(1), a_snd_nxt, b"spurious data",
    );
    pair.clear_capture();
    pair.inject_to_a(data_frame);
    pair.transfer_one();
    assert_state(pair.tcp_a(), State::CloseWait, "A still CloseWait")?;

    // RFC 9293 §3.10.7.4 seventh step: segment text is ignored in CLOSE-WAIT.
    // rcv_nxt must not advance and no data should be delivered.
    assert_ok!(
        pair.tcp_a().rcv_nxt() == rcv_nxt_before,
        "rcv_nxt advanced after data past FIN: {} → {}",
        rcv_nxt_before, pair.tcp_a().rcv_nxt()
    );
    let cap = pair.drain_captured();
    let a_sent = cap.tcp().direction(Dir::AtoB).count();
    assert_ok!(a_sent == 0, "A sent {a_sent} frame(s) in response to data past FIN");

    Ok(())
}

// ── fin_retransmit ─────────────────────────────────────────────────────────────
//
// RFC 9293 §3.8.1 (Retransmission): Drop the first FIN from A; verify RTO
// fires a retransmit with same seq.
#[test]
fn fin_retransmit() -> TestResult {
    use rawket::bridge::{Impairment, LinkProfile, PacketSpec};
    use rawket::filter;

    let mut pair = setup_tcp_pair()
        .rto_min_ms(10).time_wait_ms(100)
        .profile(LinkProfile::leased_line_100m())
        .connect();

    // Drop only the first FIN from A.
    pair.add_impairment_to_b(Impairment::Drop(PacketSpec::nth_matching(1, filter::tcp::fin())));

    pair.tcp_a_mut().close()?;

    // Advance past the actual RTO (which may exceed rto_min on latency links
    // due to SRTT from the handshake).  Use 200ms to cover any RTO value.
    pair.advance_both(200);
    pair.transfer();

    let cap = pair.drain_captured();

    // Collect all AtoB FIN frames (including dropped).
    let all_fins: Vec<_> = cap.all_tcp()
        .filter(|f| f.dir == Dir::AtoB)
        .filter(|f| f.tcp.flags.has(TcpFlags::FIN))
        .map(|f| (f.was_dropped, f.ts_ns, f))
        .collect();

    let fin_orig = all_fins.iter().find(|(d, _, _)| *d)
        .ok_or_else(|| TestFail::new("no dropped AtoB FIN (original)"))?;
    let fin_retx = all_fins.iter().find(|(d, _, _)| !*d)
        .ok_or_else(|| TestFail::new("no non-dropped AtoB FIN (retransmit)"))?;

    assert_ok!(
        fin_orig.2.tcp.seq == fin_retx.2.tcp.seq,
        "FIN retransmit seq mismatch: original={} retransmit={}",
        fin_orig.2.tcp.seq, fin_retx.2.tcp.seq,
    );

    // On a latency link, the RTO from handshake SRTT is ~80-100ms.
    // Verify the gap is in a reasonable range (50-300ms).
    let gap_ms = (fin_retx.1.saturating_sub(fin_orig.1)) / 1_000_000;
    assert_ok!(
        gap_ms >= 50 && gap_ms <= 300,
        "FIN RTO gap {gap_ms}ms not in [50, 300] — expected ~RTO"
    );

    // Drive to clean closure.
    pair.clear_impairments();
    pair.transfer();
    assert_state(pair.tcp_b(), State::CloseWait, "B CloseWait")?;
    pair.tcp_b_mut().close()?;
    pair.transfer_while(|p| {
        p.tcp_a(0).state != State::TimeWait || p.tcp_b(0).state != State::Closed
    });
    assert_state(pair.tcp_b(), State::Closed, "B Closed")?;
    pair.transfer();
    assert_state(pair.tcp_a(), State::Closed, "A Closed")?;

    Ok(())
}

// ── fin_piggybacked_on_data ────────────────────────────────────────────────────
//
// Implementation optimization: close() after send() piggybacks FIN on the
// last data segment.  RFC 9293 §3.10.4 says "form a FIN segment and send it"
// after preceding SENDs are segmentized — piggybacking is not required.
#[test]
fn fin_piggybacked_on_data() -> TestResult {
    use rawket::bridge::LinkProfile;
    let mut pair = setup_tcp_pair()
        .profile(LinkProfile::leased_line_100m())
        .connect();

    // 20 000 bytes > initial_cwnd (10*MSS ≈ 14480 bytes with TS option), so
    // flush_send_buf() cannot drain everything in send(); close() sees a
    // non-empty buffer and piggybacks FIN on the last data segment.
    let data = vec![0x50u8; 20_000];
    pair.tcp_a_mut().send(&data)?;
    pair.tcp_a_mut().close()?;

    pair.transfer_while(|p| p.tcp_b(0).state != State::CloseWait);
    assert_state(pair.tcp_b(), State::CloseWait, "B CloseWait after piggybacked FIN+data")?;

    let cap = pair.drain_captured();
    let total_data: usize = cap.tcp()
        .direction(Dir::AtoB)
        .with_data()
        .map(|f| f.payload_len)
        .sum();
    assert_ok!(total_data == 20_000, "expected 20000 data bytes from A, got {total_data}");

    let piggybacked = cap.tcp()
        .direction(Dir::AtoB)
        .any(|f| f.tcp.flags.has(TcpFlags::FIN) && f.payload_len > 0);
    assert_ok!(
        piggybacked,
        "FIN not piggybacked on data segment — close() after send() should piggyback FIN"
    );

    Ok(())
}

// ── half_close_data_delivery ───────────────────────────────────────────────────
//
// RFC 9293 §3.6 (Connection Close): Data received in FinWait1/FinWait2 must
// be delivered (not dropped).  A initiates close, reaches FinWait2, THEN B
// sends data — A must accept it.
#[test]
fn half_close_data_delivery() -> TestResult {
    use rawket::bridge::LinkProfile;
    let mut pair = setup_tcp_pair()
        .profile(LinkProfile::leased_line_100m())
        .connect();

    pair.tcp_a_mut().close()?;
    pair.transfer();
    assert_state(pair.tcp_a(), State::FinWait2, "A FinWait2 after B ACKs FIN")?;

    // B sends data while A is in FinWait2.
    pair.clear_capture();
    pair.tcp_b_mut().send(b"halfclose")?;
    let result = pair.transfer();

    // RFC 9293 §3.6: data must be delivered to the application.
    let delivered = result.a.get(&0).cloned().unwrap_or_default();
    assert_ok!(
        delivered == b"halfclose",
        "data not delivered to A's application: got {:?}",
        core::str::from_utf8(&delivered).unwrap_or("<non-utf8>")
    );

    let cap = pair.drain_captured();
    let b_data: usize = cap.tcp()
        .direction(Dir::BtoA)
        .with_data()
        .map(|f| f.payload_len)
        .sum();
    assert_ok!(b_data == 9, "expected 9 bytes from B in half-close, got {b_data}");

    // A must ACK B's data even though A has sent its FIN.
    let b_data_end = cap.tcp()
        .direction(Dir::BtoA)
        .with_data()
        .map(|f| f.tcp.seq.wrapping_add(f.payload_len as u32))
        .max()
        .ok_or_else(|| TestFail::new("no B→A data frame for ACK check"))?;

    let a_max_ack = cap.tcp()
        .direction(Dir::AtoB)
        .with_tcp_flags(TcpFlags::ACK)
        .map(|f| f.tcp.ack)
        .max()
        .ok_or_else(|| TestFail::new("no ACK from A after B's data in FinWait2"))?;
    assert_ok!(
        a_max_ack == b_data_end,
        "A's cumulative ACK ({a_max_ack}) != B's data end ({b_data_end})"
    );

    Ok(())
}

// ── rst_during_time_wait_ignored ───────────────────────────────────────────────
//
// Implementation choice per RFC 1337 (Informational): RST during TIME-WAIT
// is ignored.  Base RFC 9293 §3.10.7.4 says RST in TIME-WAIT causes CLOSED,
// but RFC 5961 §3.2 requires exact SEQ match which provides equivalent
// protection against spurious RSTs.
#[test]
fn rst_during_time_wait_ignored() -> TestResult {
    use rawket::bridge::LinkProfile;
    let mut pair = setup_tcp_pair()
        .profile(LinkProfile::leased_line_100m())
        .connect();

    pair.tcp_a_mut().close()?;
    pair.transfer();
    pair.tcp_b_mut().close()?;
    pair.transfer_while(|p| {
        p.tcp_a(0).state != State::TimeWait || p.tcp_b(0).state != State::Closed
    });
    assert_state(pair.tcp_a(), State::TimeWait, "A TimeWait")?;

    let cap = pair.drain_captured();
    let b_fin = cap.tcp()
        .direction(Dir::BtoA)
        .with_tcp_flags(TcpFlags::FIN)
        .last()
        .ok_or_else(|| TestFail::new("no BtoA FIN"))?;
    let rst_seq = b_fin.tcp.seq + 1;

    let rst = build_tcp_rst(
        pair.mac_b, pair.mac_a,
        pair.ip_b,  pair.ip_a,
        80, 12345,
        rst_seq,
    );
    pair.clear_capture();
    pair.forward(rst);
    pair.transfer_one();

    // A must still be in TimeWait immediately after RST — RST was ignored.
    assert_state(pair.tcp_a(), State::TimeWait, "A still TimeWait after RST inject")?;

    // Let the TimeWait timer expire.
    pair.transfer_while(|p| p.tcp_a(0).state == State::TimeWait);

    // Verify A sent nothing in response to the RST.
    let cap = pair.drain_captured();
    let a_sent = cap.tcp().direction(Dir::AtoB).count();
    assert_ok!(a_sent == 0, "A sent {a_sent} frame(s) in response to RST in TimeWait — expected 0");

    Ok(())
}

// ── syn_during_time_wait ──────────────────────────────────────────────────────
//
// RFC 9293 §3.6.1 MAY-2: a SYN during TIME-WAIT MAY be accepted to reopen
// the connection.  Our implementation rejects it (stays in TimeWait).  This
// test validates our implementation choice; the RFC permits either behavior.
#[test]
fn syn_during_time_wait() -> TestResult {
    use rawket::bridge::LinkProfile;
    let mut pair = setup_tcp_pair()
        .profile(LinkProfile::leased_line_100m())
        .connect();

    pair.tcp_a_mut().close()?;
    pair.transfer();
    pair.tcp_b_mut().close()?;
    pair.transfer_while(|p| {
        p.tcp_a(0).state != State::TimeWait || p.tcp_b(0).state != State::Closed
    });
    assert_state(pair.tcp_a(), State::TimeWait, "A TimeWait")?;

    let cap0 = pair.drain_captured();
    let b_fin = cap0.tcp()
        .direction(Dir::BtoA)
        .with_tcp_flags(TcpFlags::FIN)
        .last()
        .ok_or_else(|| TestFail::new("no BtoA FIN"))?;

    let new_syn = build_tcp_syn(
        pair.mac_b, pair.mac_a,
        pair.ip_b,  pair.ip_a,
        80, 12345,
        b_fin.tcp.seq + 1000,
        0,
        0x02, // SYN
        Some(1460), None, None, false,
    );
    pair.clear_capture();
    pair.forward(new_syn);
    pair.transfer_one();

    // A must still be in TimeWait immediately after SYN — SYN was rejected.
    assert_state(pair.tcp_a(), State::TimeWait, "A still TimeWait after SYN inject")?;

    // Let the TimeWait timer expire.
    pair.transfer_while(|p| p.tcp_a(0).state == State::TimeWait);

    // Our implementation rejects SYN in TIME-WAIT — no SYN-ACK sent.
    // (RFC 9293 §3.6.1 MAY-2 permits accepting it; we choose not to.)
    let cap1 = pair.drain_captured();
    let sent_syn_ack = cap1.tcp()
        .direction(Dir::AtoB)
        .with_tcp_flags(TcpFlags::SYN)
        .with_tcp_flags(TcpFlags::ACK)
        .count();
    assert_ok!(
        sent_syn_ack == 0,
        "A sent {sent_syn_ack} SYN-ACK(s) during TIME_WAIT — implementation rejects SYN here"
    );

    Ok(())
}

// ── time_wait_2msl ────────────────────────────────────────────────────────────
//
// RFC 9293 §3.6.1: TIME-WAIT must linger for 2×MSL (MUST-13).  This test
// verifies the timer mechanism with a configurable time_wait_ms=100ms, not
// that the default value satisfies 2×MSL.
#[test]
fn time_wait_2msl() -> TestResult {
    use rawket::bridge::LinkProfile;
    let mut pair = setup_tcp_pair()
        .time_wait_ms(100)
        .profile(LinkProfile::leased_line_100m())
        .connect();
    let cfg = pair.tcp_cfg.clone();

    pair.tcp_a_mut().close()?;
    pair.transfer();
    pair.tcp_b_mut().close()?;
    pair.transfer_while(|p| p.tcp_a(0).state != State::TimeWait);
    assert_state(pair.tcp_a(), State::TimeWait, "A TimeWait")?;
    let tw_start = pair.clock_a.monotonic_ns();

    pair.transfer();
    assert_state(pair.tcp_a(), State::Closed, "A Closed after 2MSL")?;

    let elapsed_ms = (pair.clock_a.monotonic_ns() - tw_start) / 1_000_000;
    assert_ok!(
        elapsed_ms == cfg.time_wait_ms as u64,
        "TimeWait lasted {elapsed_ms}ms, expected {}", cfg.time_wait_ms
    );

    Ok(())
}

// ── duplicate_fin_resets_2msl ────────────────────────────────────────────────
//
// RFC 9293 §3.6.1: A duplicate FIN received during TIME_WAIT must restart
// the 2MSL timer.  Drive to TimeWait, advance halfway through time_wait_ms,
// inject a duplicate FIN, then verify the timer restarted (full time_wait_ms
// required again).
#[test]
fn duplicate_fin_resets_2msl() -> TestResult {
    use rawket::bridge::LinkProfile;
    let mut pair = setup_tcp_pair()
        .time_wait_ms(100)
        .profile(LinkProfile::leased_line_100m())
        .connect();
    let tw_ms = pair.tcp_cfg.time_wait_ms as u64;

    pair.tcp_a_mut().close()?;
    pair.transfer();
    pair.tcp_b_mut().close()?;
    pair.transfer_while(|p| p.tcp_a(0).state != State::TimeWait);
    assert_state(pair.tcp_a(), State::TimeWait, "A TimeWait")?;
    let tw_start = pair.clock_a.monotonic_ns();

    // Capture B's FIN seq for the duplicate.
    let cap = pair.drain_captured();
    let b_fin = cap.tcp()
        .direction(Dir::BtoA)
        .with_tcp_flags(TcpFlags::FIN)
        .last()
        .ok_or_else(|| TestFail::new("no BtoA FIN for duplicate"))?;
    let fin_seq = b_fin.tcp.seq;
    let fin_ack = b_fin.tcp.ack;

    // Advance halfway through TIME_WAIT, then inject duplicate FIN.
    pair.advance_both((tw_ms / 2) as i64);

    let dup_fin = build_tcp_data_with_flags(
        pair.mac_b, pair.mac_a,
        pair.ip_b,  pair.ip_a,
        80, 12345,
        fin_seq, fin_ack,
        0x11, // FIN|ACK
        65535,
        b"",
    );
    pair.forward(dup_fin);

    // transfer() runs to Closed — the duplicate FIN should have restarted
    // the timer, so total elapsed > original time_wait_ms.
    pair.transfer();
    assert_state(pair.tcp_a(), State::Closed, "A Closed after restarted 2MSL")?;

    let elapsed_ms = (pair.clock_a.monotonic_ns() - tw_start) / 1_000_000;
    // Without restart: elapsed == tw_ms. With restart at halfway: elapsed ≈ tw_ms/2 + tw_ms.
    // The timer was restarted at tw_ms/2, so total must be at least tw_ms/2 + tw_ms.
    let expected_min = tw_ms + tw_ms / 2;
    assert_ok!(
        elapsed_ms >= expected_min,
        "TimeWait lasted {elapsed_ms}ms, expected ≥{expected_min}ms \
         (dup FIN at {tw}ms/2 should restart {tw}ms timer)", tw = tw_ms
    );

    // Verify A ACKed the duplicate FIN.
    let cap2 = pair.drain_captured();
    let a_ack = cap2.tcp()
        .direction(Dir::AtoB)
        .with_tcp_flags(TcpFlags::ACK)
        .without_tcp_flags(TcpFlags::RST)
        .count();
    assert_ok!(a_ack > 0, "A did not ACK the duplicate FIN (RFC 9293 §3.6.1)");

    Ok(())
}
