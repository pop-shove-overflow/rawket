use rawket::{
    bridge::{Impairment, LinkProfile, PacketSpec},
    filter,
    tcp::{State, TcpConfig, TcpError, TcpFlags, TcpSocket},
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

// RFC 9293 §3.8.3 (TCP Connection Failures): excessive retransmissions close
// the connection.
// With max_retransmits=4 and all data dropped, socket must close with
// error=Timeout after exactly max_retransmits+1 data sends.
#[test]
fn rto_max_retransmits() -> TestResult {
    let mut pair = setup_tcp_pair()
        .rto_min_ms(10).max_retransmits(4)
        .profile(LinkProfile::leased_line_100m())
        .connect();
    let cfg = pair.tcp_cfg.clone();

    // Drop all AtoB data frames.
    pair.add_impairment_to_b(Impairment::Drop(PacketSpec::matching(filter::tcp::has_data())));

    pair.tcp_a_mut().send(b"hello")?;
    pair.transfer_while(|p| p.tcp_a(0).state != State::Closed);

    let sock_a = pair.tcp_a();
    assert_state(sock_a, State::Closed, "A Closed after max retransmits")?;
    assert_error_fired(sock_a, TcpError::Timeout, "A error = Timeout")?;

    let cap = pair.drain_captured();

    // Implementation choice: send RST to notify peer on retransmit exhaustion.
    // RFC 9293 §3.8.3 says "close the connection" but does not mandate RST.
    let rst_count = cap.all_tcp().from_a().with_tcp_flags(TcpFlags::RST).count();
    assert_ok!(rst_count == 1, "expected 1 RST from A on timeout, got {rst_count}");

    // Count data sends: 1 original + max_retransmits RTO retransmits.
    // TLP (RFC 8985) may fire once before the first RTO when SRTT > 0
    // from the handshake — it does not increment rto_count, so it is an
    // extra send beyond the max_retransmits budget.
    let total_data = cap.all_tcp().from_a().dropped().with_data().count();
    let expected_rto = cfg.max_retransmits as usize + 1;
    let tlp_count = total_data.saturating_sub(expected_rto);
    assert_ok!(
        tlp_count <= 1,
        "expected {} data sends (1 + max_retransmits={}), got {total_data} ({tlp_count} extra — at most 1 TLP expected)",
        expected_rto, cfg.max_retransmits
    );

    Ok(())
}

// RFC 6298 §5.2: "When all outstanding data has been acknowledged, turn off
// the retransmission timer." A sends data (RTO armed); a synthetic ACK from
// B clears the unacked queue. Advancing past rto_min_ms must NOT produce a
// retransmit.
#[test]
fn rto_cleared_on_full_ack() -> TestResult {
    let mut pair = setup_tcp_pair()
        .rto_min_ms(10)
        .profile(LinkProfile::leased_line_100m())
        .connect();

    // Drop A's data so B never replies automatically.
    pair.add_impairment_to_b(Impairment::Drop(PacketSpec::matching(filter::tcp::has_data())));

    pair.tcp_a_mut().send(b"hello")?;
    // Drive until data is in-flight and RTO is armed, then stop.
    pair.transfer_while(|p| p.tcp_a(0).timer_state().rto_ns.is_none());

    // Read seq/ack from the dropped frame.
    let cap = pair.drain_captured();
    let dropped = cap.all_tcp().from_a().dropped().with_data().next()
        .ok_or_else(|| TestFail::new("no dropped data frame"))?;
    let (a_snd_una, b_snd_nxt) = (dropped.tcp.seq, dropped.tcp.ack);

    // Inject a full ACK from B (with TS so PAWS doesn't reject it).
    let ack = crate::harness::b_to_a(&pair, b_snd_nxt, a_snd_una + 5, b"");
    pair.clear_capture();
    pair.clear_impairments();
    pair.inject_to_a(ack);
    pair.transfer_one();

    // Prove the injected ACK was accepted.
    assert_ok!(
        pair.tcp_a().snd_una() == a_snd_una + 5,
        "snd_una did not advance to {} after full ACK: {}",
        a_snd_una + 5, pair.tcp_a().snd_una()
    );

    // After full ACK, RTO must be disarmed (unacked queue empty).
    let timers = pair.tcp_a().timer_state();
    assert_ok!(
        timers.rto_ns.is_none(),
        "RTO still armed after full ACK: {timers:?}"
    );

    // No spurious retransmit should have occurred.
    let cap = pair.drain_captured();
    let spurious_retx = cap.all_tcp().from_a().with_data().next().is_some();
    assert_ok!(!spurious_retx, "RTO fired despite receiving full ACK before deadline");

    Ok(())
}

// RFC 7323 §4.3: With timestamps enabled, RTT measurement via TSecr overrides
// Karn's algorithm — SRTT/RTO recover to normal values after a retransmit.
#[test]
fn timestamps_override_karn() -> TestResult {
    let mut pair = setup_tcp_pair()
        .rto_min_ms(10)
        .profile(LinkProfile::leased_line_100m())
        .connect();
    let cfg = pair.tcp_cfg.clone();

    // Force a retransmit, then let ACK come back.
    pair.add_impairment_to_b(Impairment::Drop(PacketSpec::nth_matching(1, filter::tcp::has_data())));
    pair.tcp_a_mut().send(b"hello")?;
    pair.transfer();

    let rto  = pair.tcp_a().rto_ms();
    let srtt = pair.tcp_a().srtt_ms();

    // Precondition: timestamps must be enabled for this test to be meaningful.
    // Without timestamps, Karn's algorithm would forbid RTT sampling from the
    // retransmitted segment and SRTT/RTO would not recover.
    assert_ok!(pair.tcp_a().ts_enabled(), "timestamps not enabled — test is meaningless");

    // Verify the ACK for the retransmit echoed a valid timestamp.
    let cap = pair.drain_captured();
    let retx_ack = cap.tcp().from_b()
        .filter(|f| f.tcp.opts.timestamps.is_some())
        .last();
    assert_ok!(retx_ack.is_some(), "no ACK with timestamps from B after retransmit");
    let (_, tsecr) = retx_ack.unwrap().tcp.opts.timestamps.unwrap();
    assert_ok!(tsecr > 0, "TSecr in retransmit ACK is 0 — timestamp echo not working");

    // On a latency link (20ms RTT), recovered RTO ≈ SRTT + 4*RTTVAR ≈ 80-100ms.
    // Verify it recovered below the backed-off value (not stuck at rto_max).
    assert_ok!(
        rto < cfg.rto_max_ms,
        "RTO after TS-based retransmit recovery = {rto} ms, not recovered (rto_max = {} ms)",
        cfg.rto_max_ms
    );
    assert_ok!(srtt > 0 && srtt < 100, "SRTT after TS recovery = {srtt} ms, expected 0 < srtt < 100");

    assert_state(pair.tcp_a(), State::Established, "A Established after TS-based RTT recovery")?;

    Ok(())
}

// RFC 6298 rule (2.4): "if [RTO] is less than 1 second, then the RTO SHOULD
// be rounded up to 1 second." Our implementation uses rto_min_ms (configurable).
// After fast ACKs (low RTT), RTO must still be ≥ cfg.rto_min_ms.
#[test]
fn rto_min_floor() -> TestResult {
    let mut pair = setup_tcp_pair()
        .rto_min_ms(10)
        .profile(LinkProfile::leased_line_100m())
        .connect();
    let cfg = pair.tcp_cfg.clone();

    for _ in 0..5 {
        pair.tcp_a_mut().send(b"hello-rto-min")?;
        pair.transfer();
    }

    let rto = pair.tcp_a().rto_ms();
    assert_ok!(
        rto >= cfg.rto_min_ms,
        "RTO ({rto} ms) < rto_min_ms ({} ms)", cfg.rto_min_ms
    );
    // After 5 clean exchanges, RTO should not be stuck at rto_max.
    assert_ok!(
        rto < cfg.rto_max_ms,
        "RTO ({rto} ms) == rto_max_ms after clean exchanges — not converging"
    );

    Ok(())
}

// RFC 6298 rule (2.5): "A maximum value MAY be placed on RTO provided it is at
// least 60 seconds." After 6+ RTO backoffs (all data dropped), RTO must not
// exceed rto_max_ms. Uses max_retransmits=12 so socket stays alive long enough.
#[test]
fn rto_max_ceiling() -> TestResult {
    let mut pair = setup_tcp_pair()
        .rto_max_ms(500).max_retransmits(12)
        .profile(LinkProfile::leased_line_100m())
        .connect();
    let cfg = pair.tcp_cfg.clone();

    // Drop all data from A.
    pair.add_impairment_to_b(Impairment::Drop(PacketSpec::matching(filter::tcp::has_data())));

    pair.tcp_a_mut().send(b"backoff-test")?;

    // transfer_while checks RTO at each step for ceiling violations.
    let mut reached_max = false;
    pair.transfer_while(|p| {
        if p.tcp_a(0).state == State::Closed { return false; }
        let rto = p.tcp_a(0).rto_ms();
        if rto >= cfg.rto_max_ms {
            reached_max = true;
            return false;
        }
        true
    });

    // Verify no overshoot occurred.
    let rto = pair.tcp_a().rto_ms();
    if pair.tcp_a().state != State::Closed {
        assert_ok!(
            rto <= cfg.rto_max_ms,
            "RTO ({rto} ms) > rto_max_ms ({} ms)", cfg.rto_max_ms
        );
    }
    assert_ok!(reached_max, "RTO never reached rto_max_ms — socket may have closed first");

    Ok(())
}

// RFC 6298 §5.1: "Every time a packet containing data is sent (including a
// retransmission), if the timer is not running, start it."
// After the first send(), next_deadline_ns() should return Some (timer armed).
#[test]
fn rto_armed_on_first_send() -> TestResult {
    let mut pair = setup_tcp_pair()
        .profile(LinkProfile::leased_line_100m())
        .connect();

    // After handshake, unacked queue is empty — RTO should be disarmed.
    let before = pair.tcp_a().timer_state();
    assert_ok!(
        before.rto_ns.is_none(),
        "RTO should be disarmed after handshake (no unacked data): {before:?}"
    );

    pair.tcp_a_mut().send(b"arm-test")?;
    // Don't transfer — check timers immediately after send, before ACK arrives.

    let after = pair.tcp_a().timer_state();
    assert_ok!(
        after.rto_ns.is_some(),
        "RTO not armed after first send: {after:?}"
    );
    let rto_ns = after.rto_ns.unwrap();
    assert_ok!(rto_ns > 0, "RTO deadline already expired after first send");

    // RFC 6298 §2.1: "Until a round-trip time (RTT) measurement has been
    // made [...] the sender SHOULD set RTO <- 1 second".  Our implementation
    // uses rto_min_ms as the initial RTO (default 200ms), which is a
    // deliberate divergence for faster recovery.  Verify it matches config.
    let rto_ms = rto_ns / 1_000_000;
    assert_ok!(
        rto_ms >= pair.tcp_cfg.rto_min_ms && rto_ms <= pair.tcp_cfg.rto_max_ms,
        "initial RTO ({rto_ms} ms) outside [{}, {}] ms",
        pair.tcp_cfg.rto_min_ms, pair.tcp_cfg.rto_max_ms
    );

    Ok(())
}

// RFC 6298 §2: SRTT is updated via the exponential weighted moving average
// α=1/8. After 10+ ACK rounds, SRTT should stabilize.
//
// Clock discipline: `setup_network_pair` pauses both virtual clocks.
// `send()` immediately flushes the segment (TSval = now).  To measure a
// predictable RTT we: send, drain B (gets ACK into A's queue instantly),
// advance 50 ms, drain A (processes ACK; RTT = 50 ms).
#[test]
fn rto_update_convergence() -> TestResult {
    let mut pair = setup_tcp_pair()
        .profile(LinkProfile::leased_line_100m())
        .connect();

    let mut srtts = Vec::new();
    for _ in 0..10 {
        pair.tcp_a_mut().send(b"converge")?;
        pair.transfer();
        srtts.push(pair.tcp_a().srtt_ms());
    }

    let last_3 = &srtts[srtts.len() - 3..];
    let max_srtt = *last_3.iter().max().unwrap();
    let min_srtt = *last_3.iter().min().unwrap();
    assert_ok!(max_srtt < 100, "SRTT did not converge — last 3 values: {last_3:?}");
    assert_ok!(min_srtt > 0, "SRTT still 0 after 10 rounds on a latency link — last 3: {last_3:?}");
    assert_ok!(
        max_srtt <= min_srtt * 2,
        "SRTT not stable — last 3: {last_3:?} (ratio {max_srtt}/{min_srtt}={}×)",
        max_srtt / min_srtt
    );

    Ok(())
}

// RFC 6298 §2: RTTVAR tracks the variance of RTT samples via the EWMA
// β=1/4. On a stable link, rttvar should converge to a small value relative
// to srtt.
//
// Uses a leased-line profile so link latency (~20ms RTT) dominates over
// real-time jitter.
#[test]
fn rttvar_tracks_jitter() -> TestResult {
    let mut pair = setup_tcp_pair().profile(LinkProfile::leased_line_100m()).connect();

    for _ in 0..10 {
        pair.tcp_a_mut().send(b"rttvar")?;
        pair.transfer();
    }

    let rttvar = pair.tcp_a().rttvar_ms();
    let srtt   = pair.tcp_a().srtt_ms();

    assert_ok!(srtt > 0, "srtt not updated after 10 ACK rounds");
    assert_ok!(
        rttvar <= srtt,
        "rttvar ({rttvar} ms) unreasonably large relative to srtt ({srtt} ms)"
    );

    Ok(())
}
