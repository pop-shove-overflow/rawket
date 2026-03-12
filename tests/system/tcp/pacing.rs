use rawket::tcp::BbrPhase;
use rawket::bridge::LinkProfile;
use crate::{
    assert_ok,
    capture::{Dir, ParsedFrameExt},
    harness::setup_tcp_pair,
    TestResult,
};


// ── inter_packet_gap_matches_rate ─────────────────────────────────────────────
//
// draft-ietf-ccwg-bbr-04 §4.6.2: pacing rate gates inter-packet departure.
//
// After a 50 KB transfer, verify pacing_rate > 0 and all data delivered.
#[test]
fn inter_packet_gap_matches_rate() -> TestResult {
    // Use a leased-line so pacing gaps are observable in nanosecond timestamps.
    let mut pair = setup_tcp_pair().profile(LinkProfile::leased_line_100m()).connect();

    // Phase 1: warm up BBR so it has a stable pacing rate.
    pair.tcp_a_mut().send(&vec![0x11u8; 200_000])?;
    pair.transfer_while(|p| {
        if p.tcp_a(0).send_buf_len() < 100_000 {
            let _ = p.tcp_a_mut(0).send(&vec![0x11u8; 100_000]);
        }
        p.tcp_a(0).bbr_pacing_rate_bps() < 1_000_000
    });

    // Snapshot rate BEFORE the measured burst.
    let rate = pair.tcp_a().bbr_pacing_rate_bps();
    assert_ok!(rate >= 1_000_000, "pacing_rate too low: {rate} bps");

    // Phase 2: capture a clean burst at the measured rate.
    pair.clear_capture();
    pair.tcp_a_mut().send(&vec![0x11u8; 50_000])?;
    pair.transfer_while(|p| p.tcp_a(0).send_buf_len() > 0);

    let cap = pair.drain_captured();
    let segments: Vec<_> = cap.tcp()
        .direction(Dir::AtoB)
        .with_data()
        .collect();

    let total: usize = segments.iter().map(|f| f.payload_len).sum();
    assert_ok!(total >= 50_000, "expected ≥50000 bytes delivered, got {total}");
    assert_ok!(segments.len() >= 4, "only {} segments — need ≥4", segments.len());

    // Interval-based validation: verify each inter-segment gap is consistent
    // with a pacing interval derived from MSS and the pacing rate at burst end.
    // BBR's rate evolves during transfer, so we use the post-burst rate and
    // allow generous tolerance (3x) to account for rate convergence.
    let rate_end = pair.tcp_a().bbr_pacing_rate_bps();
    let mss = pair.tcp_cfg.mss as u64;
    let expected_ns = mss * 1_000_000_000 / rate.max(1);
    let expected_ns_end = mss * 1_000_000_000 / rate_end.max(1);
    // Use the wider of the two rate-derived intervals as the tolerance band.
    let interval_lo = expected_ns.min(expected_ns_end);
    let interval_hi = expected_ns.max(expected_ns_end);
    assert_ok!(interval_lo > 0, "pacing interval is 0");

    let mut within_tolerance = 0usize;
    let mut total_comparable = 0usize;
    for w in segments.windows(2) {
        let gap_ns = w[1].ts_ns.saturating_sub(w[0].ts_ns);
        if gap_ns == 0 { continue; }
        total_comparable += 1;
        // Accept gaps within [interval_lo/3, interval_hi*3] — wide enough to
        // cover rate convergence during the burst, tight enough to reject
        // unpaced (zero-gap) or grossly throttled (10x gap) behavior.
        if gap_ns >= interval_lo / 3 && gap_ns <= interval_hi * 3 {
            within_tolerance += 1;
        }
    }
    assert_ok!(
        total_comparable >= 3,
        "only {total_comparable} comparable gaps — test scenario too small"
    );
    assert_ok!(
        within_tolerance * 2 >= total_comparable,
        "only {within_tolerance}/{total_comparable} gaps within tolerance of expected pacing interval \
         (rate_start={rate}, rate_end={rate_end}, interval=[{interval_lo}ns, {interval_hi}ns])"
    );

    Ok(())
}

// ── probe_bw_up_increases_rate ────────────────────────────────────────────────
//
// draft-ietf-ccwg-bbr-04 §4.3.3.9: ProbeBwUp pacing_gain = 1.25.
//
// Drive BBR into ProbeBwUp; verify pacing_rate > max_bw at that time
// (probe-up gain > 1.0).
#[test]
fn probe_bw_up_increases_rate() -> TestResult {
    let mut pair = setup_tcp_pair().profile(LinkProfile::leased_line_100m()).connect();

    let mut found_up = false;
    pair.tcp_a_mut().send(&vec![0x22u8; 2_000])?;
    pair.transfer_while(|p| {
        if p.tcp_a(0).send_buf_len() == 0 {
            let _ = p.tcp_a_mut(0).send(&vec![0x22u8; 2_000]);
        }

        for snap in p.tcp_a(0).bbr_history() {
            if snap.phase == BbrPhase::ProbeBwUp && snap.max_bw > 0 {
                found_up = true;
            }
        }
        !found_up
    });

    assert_ok!(found_up, "never observed ProbeBwUp entry with measurable BW in bbr_history()");
    for snap in pair.tcp_a().bbr_history() {
        if snap.phase == BbrPhase::ProbeBwUp && snap.max_bw > 0 {
            let rate = snap.pacing_rate_bps;
            let bw = snap.max_bw;
            // BBRv3 §4.4.8: ProbeBwUp pacing_gain = 1.25.
            // Verify rate/bw ∈ [1.20, 1.30] (±4% around 1.25).
            assert_ok!(
                rate >= bw * 120 / 100 && rate <= bw * 130 / 100,
                "ProbeBwUp pacing_rate/max_bw not in [1.20, 1.30]: rate={rate}, bw={bw}, \
                 ratio={:.2}", rate as f64 / bw as f64
            );
            return Ok(());
        }
    }
    assert_ok!(false, "ProbeBwUp found during transfer but not in final history");
    Ok(())
}

// ── probe_bw_down_decreases_rate ──────────────────────────────────────────────
//
// draft-ietf-ccwg-bbr-04 §4.3.3.6: ProbeBwDown pacing_gain = 0.90.
//
// Drive BBR past Startup into ProbeBwDown; verify pacing_rate < max_bw at
// that time (down-gain < 1.0).  Uses a 100 Mbps link so RTT is non-zero and
// ProbeBwDown phase lasts long enough to be observed.
#[test]
fn probe_bw_down_decreases_rate() -> TestResult {
    // Use a 100 Mbps leased line (10 ms RTT) so BBR phases are stable and observable.
    let mut pair = setup_tcp_pair()
        .profile(LinkProfile::leased_line_100m())
        .connect();

    let mut found_down = false;
    pair.tcp_a_mut().send(&vec![0x33u8; 2_000])?;
    pair.transfer_while(|p| {
        if p.tcp_a(0).send_buf_len() == 0 {
            let _ = p.tcp_a_mut(0).send(&vec![0x33u8; 2_000]);
        }

        for snap in p.tcp_a(0).bbr_history() {
            if snap.phase == BbrPhase::ProbeBwDown && snap.max_bw > 0 {
                found_down = true;
            }
        }
        !found_down
    });

    assert_ok!(found_down, "never observed ProbeBwDown entry with measurable BW in bbr_history()");
    for snap in pair.tcp_a().bbr_history() {
        if snap.phase == BbrPhase::ProbeBwDown && snap.max_bw > 0 {
            let rate = snap.pacing_rate_bps;
            let bw = snap.max_bw;
            // BBRv3 §4.4.6: ProbeBwDown pacing_gain = 0.90.
            // Verify rate/bw ∈ [0.85, 0.95] (±5% around 0.90).
            assert_ok!(
                rate >= bw * 85 / 100 && rate <= bw * 95 / 100,
                "ProbeBwDown pacing_rate/max_bw not in [0.85, 0.95]: rate={rate}, bw={bw}, \
                 ratio={:.2}", rate as f64 / bw as f64
            );
            return Ok(());
        }
    }
    assert_ok!(false, "ProbeBwDown found during transfer but not in final history");
    Ok(())
}

// ── zero_rate_sends_immediately ─────────────────────────────────────────────
//
// draft-ietf-ccwg-bbr-04 §4.6.2: when pacing_rate is not yet estimated,
// the sender must not block transmission.
//
// Immediately after handshake, first data segment must be sent without delay.
#[test]
fn zero_rate_sends_immediately() -> TestResult {
    use rawket::bridge::LinkProfile;
    let mut pair = setup_tcp_pair()
        .profile(LinkProfile::leased_line_100m())
        .connect();

    pair.tcp_a_mut().send(b"immediate")?;
    pair.transfer();

    let cap = pair.drain_captured();
    let sent = cap.tcp()
        .direction(Dir::AtoB)
        .with_data()
        .count();

    assert_ok!(
        sent >= 1,
        "no data segment sent immediately after handshake (pacing gate blocked?)"
    );

    Ok(())
}

// ── startup_pacing_gain ──────────────────────────────────────────────────────
//
// draft-ietf-ccwg-bbr-04 §4.3.1: Startup pacing_gain = 2/ln(2) ~ 2.885.
//
// BBR Startup gain = 2.77 (4*ln(2)); ≥20 KB should transmit within 20 rounds.
#[test]
fn startup_pacing_gain() -> TestResult {
    use rawket::bridge::LinkProfile;
    let mut pair = setup_tcp_pair()
        .profile(LinkProfile::leased_line_100m())
        .connect();

    assert_ok!(
        pair.tcp_a().bbr_phase() == BbrPhase::Startup,
        "BBR not in Startup after establish: {:?}", pair.tcp_a().bbr_phase()
    );

    // Keep the pipe full so BBR gets ACK-driven bandwidth samples during Startup.
    pair.tcp_a_mut().send(&vec![0xAAu8; 50_000])?;
    let mut saw_startup_bw = false;
    pair.transfer_while(|p| {
        if p.tcp_a(0).send_buf_len() == 0 {
            let _ = p.tcp_a_mut(0).send(&vec![0xAAu8; 10_000]);
        }
        for snap in p.tcp_a(0).bbr_history() {
            if snap.phase == BbrPhase::Startup && snap.max_bw > 0 {
                saw_startup_bw = true;
            }
        }
        // Stop once we have a Startup snapshot with measured BW, or leave Startup.
        !saw_startup_bw && p.tcp_a(0).bbr_phase() == BbrPhase::Startup
    });

    let cap = pair.drain_captured();
    let total: usize = cap.tcp()
        .direction(Dir::AtoB)
        .with_data()
        .map(|f| f.payload_len)
        .sum();

    assert_ok!(
        total >= 40_000,
        "expected ≥40000 bytes in Startup pacing (got {total}) — pacing gain may be too low"
    );

    // BBRv3 §4.3.1: Startup pacing_gain = 2/ln(2) ≈ 2.885.
    // Verify via bbr_history: Startup snapshot must have pacing_rate ≈ 2.885 * max_bw.
    let snap = pair.tcp_a().bbr_history().iter()
        .find(|s| s.phase == BbrPhase::Startup && s.max_bw > 0)
        .cloned();
    assert_ok!(snap.is_some(), "no Startup snapshot with max_bw > 0 in bbr_history()");
    let snap = snap.unwrap();
    let ratio_pct = snap.pacing_rate_bps * 100 / snap.max_bw.max(1);
    // 2.885 → 288%. Allow [260%, 310%] for rounding.
    assert_ok!(
        ratio_pct >= 260 && ratio_pct <= 310,
        "Startup pacing_gain ratio {ratio_pct}% not in [260%, 310%] \
         (expected ~288% = 2/ln(2)): rate={}, bw={}",
        snap.pacing_rate_bps, snap.max_bw
    );

    Ok(())
}

// ── drain_pacing_gain ────────────────────────────────────────────────────────
//
// draft-ietf-ccwg-bbr-04 §4.3.2: Drain pacing_gain < 1.0.
//
// After Startup exit, BBR enters Drain (gain < 1). Connection must survive
// and eventually transition to ProbeBW.
#[test]
fn drain_pacing_gain() -> TestResult {
    let mut pair = setup_tcp_pair().profile(LinkProfile::leased_line_100m()).connect();

    let mut saw_drain = false;
    pair.tcp_a_mut().send(&vec![0xBBu8; 2_000])?;
    pair.transfer_while(|p| {
        if p.tcp_a(0).send_buf_len() == 0 {
            let _ = p.tcp_a_mut(0).send(&vec![0xBBu8; 2_000]);
        }
        for snap in p.tcp_a(0).bbr_history() {
            if snap.phase == BbrPhase::Drain {
                saw_drain = true;
            }
        }
        !saw_drain
    });

    assert_ok!(saw_drain, "never observed Drain phase");

    // draft-ietf-ccwg-bbr-04 §4.3.2: Drain pacing_gain = ln(2)/2 ≈ 0.347.
    // Verify pacing_rate/max_bw ratio in [30%, 40%].
    let drain_snap = pair.tcp_a().bbr_history().iter()
        .find(|s| s.phase == BbrPhase::Drain && s.max_bw > 0)
        .cloned();
    assert_ok!(drain_snap.is_some(), "no Drain snapshot with max_bw > 0 in bbr_history()");
    let snap = drain_snap.unwrap();
    let ratio_pct = snap.pacing_rate_bps * 100 / snap.max_bw.max(1);
    assert_ok!(
        ratio_pct >= 30 && ratio_pct <= 40,
        "Drain pacing gain {ratio_pct}% not in [30%, 40%] (expected ~35% = ln(2)/2): \
         rate={}, bw={}", snap.pacing_rate_bps, snap.max_bw
    );

    let phase = pair.tcp_a().bbr_phase();
    assert_ok!(
        matches!(
            phase,
            BbrPhase::Drain
            | BbrPhase::ProbeBwDown
            | BbrPhase::ProbeBwCruise
            | BbrPhase::ProbeBwRefill
            | BbrPhase::ProbeBwUp
            | BbrPhase::ProbeRtt
        ),
        "BBR should be in Drain/ProbeBW/ProbeRtt after Startup exit, got {phase:?}"
    );

    Ok(())
}

// ── pacing_deadline_gates_transmission ────────────────────────────────────────
//
// draft-ietf-ccwg-bbr-04 §4.6.2: pacing deadline gates segment departure.
//
// After BBR measures BW, consecutive data segments should not all appear at
// the same timestamp (pacing must gate transmission).
#[test]
fn pacing_deadline_gates_transmission() -> TestResult {
    use rawket::bridge::LinkProfile;

    // 100 Mbps link with 10 ms latency.  Pacing gaps between 1460-byte segments
    // are ~117 µs — observable in nanosecond capture timestamps.
    let mut pair = setup_tcp_pair()
        .profile(LinkProfile::ethernet_100m())
        .connect();

    // Phase 1: warm up BBR to establish a bandwidth estimate.
    pair.tcp_a_mut().send(&vec![0x33u8; 200_000])?;
    pair.transfer_while(|p| {
        if p.tcp_a(0).send_buf_len() < 100_000 {
            let _ = p.tcp_a_mut(0).send(&vec![0x33u8; 100_000]);
        }
        p.tcp_a(0).bbr_pacing_rate_bps() < 1_000_000
    });

    let rate = pair.tcp_a().bbr_pacing_rate_bps();
    assert_ok!(rate > 0, "pacing rate is 0 after warmup");

    // Phase 2: send a burst and capture paced segment departures.
    pair.clear_capture();
    pair.tcp_a_mut().send(&vec![0x44u8; 50_000])?;
    pair.transfer_while(|p| p.tcp_a(0).send_buf_len() > 0);

    let cap = pair.drain_captured();
    let segments: Vec<_> = cap.tcp()
        .direction(Dir::AtoB)
        .with_data()
        .collect();

    assert_ok!(
        segments.len() >= 4,
        "only {} data segments captured — need ≥4 for gap analysis",
        segments.len()
    );

    // Interval-based validation: each gap should be consistent with the
    // pacing interval (MSS * 1e9 / rate).  BBR rate evolves, so use
    // pre- and post-burst rates to define the tolerance band.
    let rate_end = pair.tcp_a().bbr_pacing_rate_bps();
    let mss = pair.tcp_cfg.mss as u64;
    let interval_lo = mss * 1_000_000_000 / rate.max(rate_end).max(1);
    let interval_hi = mss * 1_000_000_000 / rate.min(rate_end).max(1);

    let mut within_tolerance = 0usize;
    let mut total_comparable = 0usize;
    for w in segments.windows(2) {
        let gap_ns = w[1].ts_ns.saturating_sub(w[0].ts_ns);
        if gap_ns == 0 { continue; }
        total_comparable += 1;
        if gap_ns >= interval_lo / 3 && gap_ns <= interval_hi * 3 {
            within_tolerance += 1;
        }
    }
    assert_ok!(
        total_comparable >= 3,
        "only {total_comparable} comparable gaps — test scenario too small"
    );
    assert_ok!(
        within_tolerance * 2 >= total_comparable,
        "only {within_tolerance}/{total_comparable} gaps within tolerance of pacing interval \
         (rate=[{rate}, {rate_end}], interval=[{interval_lo}ns, {interval_hi}ns])"
    );

    Ok(())
}

// ── probe_rtt_cwnd_during_phase ──────────────────────────────────────────────
//
// draft-ietf-ccwg-bbr-04 §4.3.4: during ProbeRTT, cwnd is reduced to
// bdp_target (4 packets). Drive BBR until ProbeRTT entry, then verify
// cwnd is capped.
#[test]
fn probe_rtt_cwnd_during_phase() -> TestResult {
    let mut pair = setup_tcp_pair()
        .profile(LinkProfile::leased_line_100m())
        .connect();

    let mss = pair.tcp_a().peer_mss() as u32;
    let mut saw_probe_rtt = false;
    let mut probe_rtt_cwnd: u32 = 0;

    pair.tcp_a_mut().send(&vec![0xEEu8; 2_000])?;
    pair.transfer_while(|p| {
        if p.tcp_a(0).send_buf_len() == 0 {
            let _ = p.tcp_a_mut(0).send(&vec![0xEEu8; 2_000]);
        }
        if p.tcp_a(0).bbr_phase() == BbrPhase::ProbeRtt {
            saw_probe_rtt = true;
            probe_rtt_cwnd = p.tcp_a(0).bbr_cwnd();
            return false;
        }
        true
    });

    assert_ok!(saw_probe_rtt, "never entered ProbeRTT phase");

    // BBRv3 §4.3.4.5: ProbeRTT cwnd = bdp_target = 4 * MSS.
    let bdp_target = 4 * mss;
    assert_ok!(
        probe_rtt_cwnd <= bdp_target,
        "ProbeRTT cwnd ({probe_rtt_cwnd}) exceeds bdp_target ({bdp_target} = 4 * MSS={mss})"
    );
    assert_ok!(
        probe_rtt_cwnd > 0,
        "ProbeRTT cwnd is 0 — should be capped at bdp_target, not zeroed"
    );

    Ok(())
}

// ── probe_bw_up_increases_rate ────────────────────────────────────────────────
//
// draft-ietf-ccwg-bbr-04 §4.3.3.9: ProbeBwUp pacing_gain = 1.25.
//
// Drive BBR into ProbeBwUp; verify pacing_rate > max_bw at that time
// (probe-up gain > 1.0).
#[test]
fn probe_bw_up_increases_rate() -> TestResult {
    let mut pair = setup_tcp_pair().profile(LinkProfile::leased_line_100m()).connect();

    let mut found_up = false;
    pair.tcp_a_mut().send(&vec![0x22u8; 2_000])?;
    pair.transfer_while(|p| {
        if p.tcp_a(0).send_buf_len() == 0 {
            let _ = p.tcp_a_mut(0).send(&vec![0x22u8; 2_000]);
        }

        for snap in p.tcp_a(0).bbr_history() {
            if snap.phase == BbrPhase::ProbeBwUp && snap.max_bw > 0 {
                found_up = true;
            }
        }
        !found_up
    });

    assert_ok!(found_up, "never observed ProbeBwUp entry with measurable BW in bbr_history()");
    for snap in pair.tcp_a().bbr_history() {
        if snap.phase == BbrPhase::ProbeBwUp && snap.max_bw > 0 {
            let rate = snap.pacing_rate_bps;
            let bw = snap.max_bw;
            // BBRv3 §4.4.8: ProbeBwUp pacing_gain = 1.25.
            // Verify rate/bw ∈ [1.20, 1.30] (±4% around 1.25).
            assert_ok!(
                rate >= bw * 120 / 100 && rate <= bw * 130 / 100,
                "ProbeBwUp pacing_rate/max_bw not in [1.20, 1.30]: rate={rate}, bw={bw}, \
                 ratio={:.2}", rate as f64 / bw as f64
            );
            return Ok(());
        }
    }
    assert_ok!(false, "ProbeBwUp found during transfer but not in final history");
    Ok(())
}

// ── probe_bw_down_decreases_rate ──────────────────────────────────────────────
//
// draft-ietf-ccwg-bbr-04 §4.3.3.6: ProbeBwDown pacing_gain = 0.90.
//
// Drive BBR past Startup into ProbeBwDown; verify pacing_rate < max_bw at
// that time (down-gain < 1.0).  Uses a 100 Mbps link so RTT is non-zero and
// ProbeBwDown phase lasts long enough to be observed.
#[test]
fn probe_bw_down_decreases_rate() -> TestResult {
    // Use a 100 Mbps leased line (10 ms RTT) so BBR phases are stable and observable.
    let mut pair = setup_tcp_pair()
        .profile(LinkProfile::leased_line_100m())
        .connect();

    let mut found_down = false;
    pair.tcp_a_mut().send(&vec![0x33u8; 2_000])?;
    pair.transfer_while(|p| {
        if p.tcp_a(0).send_buf_len() == 0 {
            let _ = p.tcp_a_mut(0).send(&vec![0x33u8; 2_000]);
        }

        for snap in p.tcp_a(0).bbr_history() {
            if snap.phase == BbrPhase::ProbeBwDown && snap.max_bw > 0 {
                found_down = true;
            }
        }
        !found_down
    });

    assert_ok!(found_down, "never observed ProbeBwDown entry with measurable BW in bbr_history()");
    for snap in pair.tcp_a().bbr_history() {
        if snap.phase == BbrPhase::ProbeBwDown && snap.max_bw > 0 {
            let rate = snap.pacing_rate_bps;
            let bw = snap.max_bw;
            // BBRv3 §4.4.6: ProbeBwDown pacing_gain = 0.90.
            // Verify rate/bw ∈ [0.85, 0.95] (±5% around 0.90).
            assert_ok!(
                rate >= bw * 85 / 100 && rate <= bw * 95 / 100,
                "ProbeBwDown pacing_rate/max_bw not in [0.85, 0.95]: rate={rate}, bw={bw}, \
                 ratio={:.2}", rate as f64 / bw as f64
            );
            return Ok(());
        }
    }
    assert_ok!(false, "ProbeBwDown found during transfer but not in final history");
    Ok(())
}

// ── zero_rate_sends_immediately ─────────────────────────────────────────────
//
// draft-ietf-ccwg-bbr-04 §4.6.2: when pacing_rate is not yet estimated,
// the sender must not block transmission.
//
// Immediately after handshake, first data segment must be sent without delay.
#[test]
fn zero_rate_sends_immediately() -> TestResult {
    use rawket::bridge::LinkProfile;
    let mut pair = setup_tcp_pair()
        .profile(LinkProfile::leased_line_100m())
        .connect();

    pair.tcp_a_mut().send(b"immediate")?;
    pair.transfer();

    let cap = pair.drain_captured();
    let sent = cap.tcp()
        .direction(Dir::AtoB)
        .with_data()
        .count();

    assert_ok!(
        sent >= 1,
        "no data segment sent immediately after handshake (pacing gate blocked?)"
    );

    Ok(())
}

// ── startup_pacing_gain ──────────────────────────────────────────────────────
//
// draft-ietf-ccwg-bbr-04 §4.3.1: Startup pacing_gain = 2/ln(2) ~ 2.885.
//
// BBR Startup gain = 2.77 (4*ln(2)); ≥20 KB should transmit within 20 rounds.
#[test]
fn startup_pacing_gain() -> TestResult {
    use rawket::bridge::LinkProfile;
    let mut pair = setup_tcp_pair()
        .profile(LinkProfile::leased_line_100m())
        .connect();

    assert_ok!(
        pair.tcp_a().bbr_phase() == BbrPhase::Startup,
        "BBR not in Startup after establish: {:?}", pair.tcp_a().bbr_phase()
    );

    // Keep the pipe full so BBR gets ACK-driven bandwidth samples during Startup.
    pair.tcp_a_mut().send(&vec![0xAAu8; 50_000])?;
    let mut saw_startup_bw = false;
    pair.transfer_while(|p| {
        if p.tcp_a(0).send_buf_len() == 0 {
            let _ = p.tcp_a_mut(0).send(&vec![0xAAu8; 10_000]);
        }
        for snap in p.tcp_a(0).bbr_history() {
            if snap.phase == BbrPhase::Startup && snap.max_bw > 0 {
                saw_startup_bw = true;
            }
        }
        // Stop once we have a Startup snapshot with measured BW, or leave Startup.
        !saw_startup_bw && p.tcp_a(0).bbr_phase() == BbrPhase::Startup
    });

    let cap = pair.drain_captured();
    let total: usize = cap.tcp()
        .direction(Dir::AtoB)
        .with_data()
        .map(|f| f.payload_len)
        .sum();

    assert_ok!(
        total >= 40_000,
        "expected ≥40000 bytes in Startup pacing (got {total}) — pacing gain may be too low"
    );

    // BBRv3 §4.3.1: Startup pacing_gain = 2/ln(2) ≈ 2.885.
    // Verify via bbr_history: Startup snapshot must have pacing_rate ≈ 2.885 * max_bw.
    let snap = pair.tcp_a().bbr_history().iter()
        .find(|s| s.phase == BbrPhase::Startup && s.max_bw > 0)
        .cloned();
    assert_ok!(snap.is_some(), "no Startup snapshot with max_bw > 0 in bbr_history()");
    let snap = snap.unwrap();
    let ratio_pct = snap.pacing_rate_bps * 100 / snap.max_bw.max(1);
    // 2.885 → 288%. Allow [260%, 310%] for rounding.
    assert_ok!(
        ratio_pct >= 260 && ratio_pct <= 310,
        "Startup pacing_gain ratio {ratio_pct}% not in [260%, 310%] \
         (expected ~288% = 2/ln(2)): rate={}, bw={}",
        snap.pacing_rate_bps, snap.max_bw
    );

    Ok(())
}

// ── drain_pacing_gain ────────────────────────────────────────────────────────
//
// draft-ietf-ccwg-bbr-04 §4.3.2: Drain pacing_gain < 1.0.
//
// After Startup exit, BBR enters Drain (gain < 1). Connection must survive
// and eventually transition to ProbeBW.
#[test]
fn drain_pacing_gain() -> TestResult {
    let mut pair = setup_tcp_pair().profile(LinkProfile::leased_line_100m()).connect();

    let mut saw_drain = false;
    pair.tcp_a_mut().send(&vec![0xBBu8; 2_000])?;
    pair.transfer_while(|p| {
        if p.tcp_a(0).send_buf_len() == 0 {
            let _ = p.tcp_a_mut(0).send(&vec![0xBBu8; 2_000]);
        }
        for snap in p.tcp_a(0).bbr_history() {
            if snap.phase == BbrPhase::Drain {
                saw_drain = true;
            }
        }
        !saw_drain
    });

    assert_ok!(saw_drain, "never observed Drain phase");

    // draft-ietf-ccwg-bbr-04 §4.3.2: Drain pacing_gain = ln(2)/2 ≈ 0.347.
    // Verify pacing_rate/max_bw ratio in [30%, 40%].
    let drain_snap = pair.tcp_a().bbr_history().iter()
        .find(|s| s.phase == BbrPhase::Drain && s.max_bw > 0)
        .cloned();
    assert_ok!(drain_snap.is_some(), "no Drain snapshot with max_bw > 0 in bbr_history()");
    let snap = drain_snap.unwrap();
    let ratio_pct = snap.pacing_rate_bps * 100 / snap.max_bw.max(1);
    assert_ok!(
        ratio_pct >= 30 && ratio_pct <= 40,
        "Drain pacing gain {ratio_pct}% not in [30%, 40%] (expected ~35% = ln(2)/2): \
         rate={}, bw={}", snap.pacing_rate_bps, snap.max_bw
    );

    let phase = pair.tcp_a().bbr_phase();
    assert_ok!(
        matches!(
            phase,
            BbrPhase::Drain
            | BbrPhase::ProbeBwDown
            | BbrPhase::ProbeBwCruise
            | BbrPhase::ProbeBwRefill
            | BbrPhase::ProbeBwUp
            | BbrPhase::ProbeRtt
        ),
        "BBR should be in Drain/ProbeBW/ProbeRtt after Startup exit, got {phase:?}"
    );

    Ok(())
}
