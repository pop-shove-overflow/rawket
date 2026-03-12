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
