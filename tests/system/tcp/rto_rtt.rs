use rawket::{
    bridge::{Impairment, LinkProfile, PacketSpec},
    filter,
    tcp::{State, TcpError, TcpSocket},
};
use crate::{
    assert::{assert_error_fired, assert_gap_approx, assert_state, assert_timestamps_present, TestFail},
    assert_ok,
    capture::ParsedFrameExt,
    harness::{setup_network_pair, setup_tcp_pair},
    packet::build_tcp_data,
    TestResult,
};
use std::net::Ipv4Addr;

// RFC 6298 §5: RTO timer fires when no ACK arrives within the computed
// timeout.  Use an instant link so SRTT stays 0 after handshake — TLP
// requires SRTT > 0 (our implementation choice), so only RTO can fire.
// Drop first frame; verify the retransmit fires at approximately rto_min.
#[test]
fn initial_rto() -> TestResult {
    // Instant link: SRTT stays 0 after handshake, so TLP won't arm
    // (our implementation requires SRTT > 0).  Only RTO can fire.
    let mut pair = setup_tcp_pair().connect();

    assert_ok!(pair.tcp_a().srtt_ms() == 0, "SRTT should be 0 on instant link");

    // Drop first data frame.
    pair.add_impairment_to_b(Impairment::Drop(PacketSpec::nth_matching(1, filter::tcp::has_data())));
    pair.tcp_a_mut().send(b"hello")?;

    let rto = pair.tcp_a().rto_ms();
    pair.transfer();

    let cap = pair.drain_captured();
    let orig = cap.all_tcp().from_a().dropped().with_data().next()
        .ok_or_else(|| TestFail::new("no dropped AtoB data frame"))?;
    let retx = cap.all_tcp().from_a().delivered().with_data()
        .find(|f| f.tcp.seq == orig.tcp.seq)
        .ok_or_else(|| TestFail::new("no retransmitted AtoB data frame"))?;

    // RFC 6298 §5: retransmit gap should match the RTO value (±30%).
    let gap = retx.ms_since(&orig);
    assert_ok!(
        gap >= rto * 7 / 10 && gap <= rto * 13 / 10,
        "retransmit gap {gap}ms not ≈ RTO ({rto}ms) [expected {}-{}]",
        rto * 7 / 10, rto * 13 / 10
    );

    Ok(())
}

// RFC 6298 §5.5: "The host MUST set RTO <- RTO * 2 ('back off the timer')."
// With all data frames dropped, the RTO interval must double after each
// retransmit: first gap ≈ rto, second gap ≈ 2×rto.
#[test]
fn rto_exponential_backoff() -> TestResult {
    let mut pair = setup_tcp_pair()
        .rto_min_ms(10).max_retransmits(4)
        .profile(LinkProfile::leased_line_100m())
        .connect();

    // Drop all AtoB data frames — drives retransmits to exhaustion.
    pair.add_impairment_to_b(Impairment::Drop(PacketSpec::matching(filter::tcp::has_data())));

    pair.tcp_a_mut().send(b"hello")?;
    pair.transfer();

    let cap = pair.drain_captured();
    let retransmits: Vec<_> = cap.all_tcp().from_a().dropped().with_data().collect();

    // Original send + max_retransmits retransmits; a TLP probe may add 1 more.
    assert_ok!(
        retransmits.len() >= 4,
        "expected ≥4 dropped data frames for backoff check, got {}", retransmits.len()
    );

    // Verify exponential backoff: each gap should be ≈2× the previous.
    // Use the last 4 frames (skips any TLP that may precede the first RTO).
    let t = &retransmits[retransmits.len() - 4..];
    let gap1 = t[1].ms_since(&t[0]);
    let gap2 = t[2].ms_since(&t[1]);
    let gap3 = t[3].ms_since(&t[2]);
    // RFC 6298 §5.5: "The host MUST set RTO <- RTO * 2 ('back off the timer')."
    // Allow ±20% for timer granularity.
    assert_ok!(gap2 >= gap1 * 8 / 5 && gap2 <= gap1 * 12 / 5,
        "gap2 ({gap2} ms) not ≈2× gap1 ({gap1} ms) [expected {}-{}]",
        gap1 * 8 / 5, gap1 * 12 / 5);
    assert_ok!(gap3 >= gap2 * 8 / 5 && gap3 <= gap2 * 12 / 5,
        "gap3 ({gap3} ms) not ≈2× gap2 ({gap2} ms) [expected {}-{}]",
        gap2 * 8 / 5, gap2 * 12 / 5);

    // RFC 7323 §3.2: RTO retransmits must carry timestamps.
    let retx = cap.all_tcp().from_a().dropped().with_data().next()
        .ok_or_else(|| TestFail::new("no RTO retransmit frame"))?;
    assert_timestamps_present(&retx, "RTO retransmit")?;

    Ok(())
}

// RFC 7323 §4.1: Timestamps enable per-segment RTT measurement. After a
// retransmit is ACKed, timestamps allow accurate RTT sampling so RTO
// recovers to a reasonable value (not stuck at rto_max from backoff).
#[test]
fn rto_recovery_after_retransmit() -> TestResult {
    // Leased-line (~20ms RTT) so the backed-off RTO is measurably larger
    // than the recovered value.
    let mut pair = setup_tcp_pair()
        .rto_min_ms(10)
        .profile(LinkProfile::leased_line_100m())
        .connect();

    // Drop ALL data so neither original nor TLP probe gets through.
    // This forces RTO to fire and back off.
    pair.add_impairment_to_b(Impairment::Drop(PacketSpec::matching(filter::tcp::has_data())));
    pair.tcp_a_mut().send(b"hello")?;

    // RTO must be armed after send (data is unacked).
    assert_ok!(
        pair.tcp_a().timer_state().rto_ns.is_some(),
        "RTO not armed after send"
    );

    // transfer_while until RTO backs off (retransmit sent).
    let rto = pair.tcp_a().rto_ms();
    pair.transfer_while(|p| p.tcp_a(0).rto_ms() <= rto);

    let rto_backed_off = pair.tcp_a().rto_ms();
    assert_ok!(
        rto_backed_off > rto,
        "RTO should be backed off after retransmit: {rto_backed_off} ms vs initial {rto} ms"
    );

    // Clear impairments so the retransmit reaches B and ACK comes back.
    pair.clear_impairments();
    pair.transfer();

    let rto_after = pair.tcp_a().rto_ms();
    assert_ok!(
        rto_after < rto_backed_off,
        "RTO did not recover: backed_off={rto_backed_off} ms, after={rto_after} ms"
    );
    // After recovery with all data ACKed, RTO should be disarmed (nothing
    // left to retransmit).  If still armed, verify it's at the recovered value.
    let timers = pair.tcp_a().timer_state();
    if let Some(rto_remaining_ns) = timers.rto_ns {
        let remaining_ms = rto_remaining_ns / 1_000_000;
        assert_ok!(
            remaining_ms <= rto_after + 1,
            "RTO remaining ({remaining_ms} ms) > recovered rto ({rto_after} ms)"
        );
    }
    // Either RTO is disarmed (all ACKed) or armed at the recovered value — both valid.
    assert_ok!(
        pair.tcp_a().state == State::Established,
        "A not Established after retransmit ACK: {:?}", pair.tcp_a().state
    );

    Ok(())
}
