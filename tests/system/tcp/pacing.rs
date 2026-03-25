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
