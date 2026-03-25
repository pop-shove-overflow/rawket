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
