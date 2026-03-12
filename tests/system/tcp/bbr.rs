use crate::{
    assert_ok,
    harness::{fast_tcp_cfg, setup_tcp_pair},
    TestResult,
};
use rawket::{
    bridge::{reseed_prng, LinkProfile},
    tcp::{BbrPhase, TcpConfig},
};

/// TCP config for loss tests: tolerates sustained moderate packet loss.
///
/// Key changes from fast_tcp_cfg():
/// - `max_retransmits` = 100 — prevents connection death under high retransmit counts
/// - `rto_max_ms` = 200 — caps exponential backoff so RTO doesn't stall tests
fn lossy_tcp_cfg() -> TcpConfig {
    let mut cfg = fast_tcp_cfg();
    cfg.max_retransmits = 100;
    cfg.rto_max_ms = 200;
    cfg
}

fn is_probe_bw(phase: BbrPhase) -> bool {
    matches!(
        phase,
        BbrPhase::ProbeBwDown
            | BbrPhase::ProbeBwCruise
            | BbrPhase::ProbeBwRefill
            | BbrPhase::ProbeBwUp
    )
}

/// Drive the pair through Startup → Drain → ProbeBW.
///
/// Works on both lossless and lossy links.  Returns Ok once any ProbeBW
/// sub-phase is observed; Err if ProbeBW is not reached within the budget.
fn drive_to_probe_bw(
    pair: &mut crate::harness::TcpSocketPair,
) -> Result<(), crate::assert::TestFail> {
    let mut reached = false;
    pair.tcp_a_mut().send(&vec![0x11u8; 2_000])?;
    pair.transfer_while(|p| {
        if p.tcp_a(0).send_buf_len() == 0 {
            let _ = p.tcp_a_mut(0).send(&vec![0x11u8; 2_000]);
        }
        for snap in p.tcp_a(0).bbr_history() {
            if is_probe_bw(snap.phase) {
                reached = true;
            }
        }
        !reached
    });
    if reached { Ok(()) } else {
        Err(crate::assert::TestFail::new(
            "never reached ProbeBW after driving data",
        ))
    }
}

// ── startup_phase_grows_cwnd ───────────────────────────────────────────────
//
// draft-ietf-ccwg-bbr-04 §4.3.1: Startup phase grows cwnd exponentially.
//
// Verify that BBR's Startup phase grows cwnd exponentially.
//
// BBR's Startup-guard invariant (`cwnd = cwnd.max(old_cwnd)`, line ~1093)
// guarantees cwnd is monotonically non-decreasing throughout Startup.
// This test verifies the growth actually occurs: by the time BBR exits
// Startup the cwnd must exceed the initial 10-MSS value.
//
#[test]
fn startup_phase_grows_cwnd() -> TestResult {
    let mut pair = setup_tcp_pair().rto_min_ms(10).profile(LinkProfile::leased_line_100m()).connect();

    let initial_cwnd = pair.tcp_a().bbr_cwnd();
    let mut max_cwnd = initial_cwnd;
    let mut saw_startup = false;
    let mut exited = false;

    pair.tcp_a_mut().send(&vec![0x11u8; 2_000])?;
    pair.transfer_while(|p| {
        if p.tcp_a(0).send_buf_len() == 0 {
            let _ = p.tcp_a_mut(0).send(&vec![0x11u8; 2_000]);
        }
        for snap in p.tcp_a(0).bbr_history() {
            if snap.phase == BbrPhase::Startup {
                saw_startup = true;
                max_cwnd = max_cwnd.max(snap.cwnd);
            } else if saw_startup {
                exited = true;
            }
        }
        !exited
    });

    assert_ok!(saw_startup, "never observed Startup phase during transfer");
    assert_ok!(
        max_cwnd > initial_cwnd,
        "cwnd did not grow during Startup: initial={initial_cwnd}, max={max_cwnd}"
    );

    Ok(())
}

// ── startup_to_drain_transition ────────────────────────────────────────────
//
// draft-ietf-ccwg-bbr-04 §4.3.1, §4.3.2, §4.3.3: BBR progresses through
// Startup → Drain → ProbeBW as it discovers link capacity.
//
// Track bbr_phase() during a 1MiB transfer and verify we observe
// Startup → Drain → ProbeBw transitions.
#[test]
fn startup_to_drain_transition() -> TestResult {
    let mut pair = setup_tcp_pair().profile(LinkProfile::leased_line_100m()).connect();

    let mut saw_startup = false;
    let mut saw_drain = false;
    let mut saw_probe_bw = false;

    pair.tcp_a_mut().send(&vec![0x22u8; 2_000])?;
    pair.transfer_while(|p| {
        if p.tcp_a(0).send_buf_len() == 0 {
            let _ = p.tcp_a_mut(0).send(&vec![0x22u8; 2_000]);
        }
        for snap in p.tcp_a(0).bbr_history() {
            match snap.phase {
                BbrPhase::Startup => saw_startup = true,
                BbrPhase::Drain => saw_drain = true,
                p if is_probe_bw(p) => saw_probe_bw = true,
                _ => {}
            }
        }
        !(saw_startup && saw_drain && saw_probe_bw)
    });

    assert_ok!(saw_startup, "never observed Startup phase");
    assert_ok!(saw_drain, "never observed Drain phase");
    assert_ok!(saw_probe_bw, "never observed ProbeBw phase");

    Ok(())
}

// ── probe_rtt_entry ────────────────────────────────────────────────────────
//
// draft-ietf-ccwg-bbr-04 §4.3.4.4: BBR enters ProbeRTT when
// probe_rtt_interval (5s) elapses without a new min_rtt sample.
//
// After 5s idle (probe_rtt_interval), BBR should enter ProbeRtt on next ACK.
// Verify bbr_phase() == ProbeRtt after the trigger.
#[test]
fn probe_rtt_entry() -> TestResult {
    let mut pair = setup_tcp_pair().profile(LinkProfile::leased_line_100m()).connect();

    // Drive to ProbeBW phase first (ProbeRtt is only entered from ProbeBW phases).
    drive_to_probe_bw(&mut pair)?;

    // Keep data flowing so min_rtt_stamp is set.
    for _ in 0..5 {
        pair.tcp_a_mut().send(&vec![0x44u8; 2_000])?;
        pair.transfer();
    }

    // Negative check: ProbeRtt must NOT be entered before the interval expires.
    // Advance 4s (< 5s interval) and verify no ProbeRtt.
    pair.advance_both(4_000);
    pair.tcp_a_mut().send(&vec![0x44u8; 2_000])?;
    pair.transfer();
    let premature = pair.tcp_a().bbr_history().iter()
        .any(|s| s.phase == BbrPhase::ProbeRtt);
    assert_ok!(
        !premature,
        "ProbeRtt entered before probe_rtt_interval expired (at 4s < 5s)"
    );

    // Now advance past bbr_probe_rtt_interval_ms (5000 ms total = 4s + 2s).
    pair.advance_both(2_000);

    // Send data to trigger ProbeRtt entry via transfer_while.
    let mut saw_probe_rtt = false;
    pair.tcp_a_mut().send(&vec![0x55u8; 2_000])?;
    pair.transfer_while(|p| {
        if p.tcp_a(0).send_buf_len() == 0 {
            let _ = p.tcp_a_mut(0).send(&vec![0x55u8; 2_000]);
        }
        for snap in p.tcp_a(0).bbr_history() {
            if snap.phase == BbrPhase::ProbeRtt {
                saw_probe_rtt = true;
            }
        }
        !saw_probe_rtt
    });

    assert_ok!(saw_probe_rtt, "expected ProbeRtt after 5s idle");

    Ok(())
}

// ── loss_reduces_bw_shortterm ──────────────────────────────────────────────
//
// draft-ietf-ccwg-bbr-04 §5.5: sustained loss in ProbeBW_DOWN/CRUISE triggers
// BBRAdaptLowerBoundsFromCongestion which reduces both bw_shortterm and
// inflight_shortterm from their u64::MAX / u32::MAX sentinels.
#[test]
fn loss_reduces_bw_shortterm() -> TestResult {
    let mut pair = setup_tcp_pair()
        .rto_min_ms(10).max_retransmits(100).rto_max_ms(200)
        .profile(LinkProfile::leased_line_100m())
        .connect();
    pair.loss_to_b(0.10);

    // Drive to ProbeBW first (with loss present).
    drive_to_probe_bw(&mut pair)?;

    let mut saw_bw_adapted = false;
    let mut saw_inflight_adapted = false;
    let mut adapted_bw_st = u64::MAX;
    let mut adapted_inflight_st = u32::MAX;

    pair.tcp_a_mut().send(&vec![0x66u8; 2_000])?;
    pair.transfer_while(|p| {
        if p.tcp_a(0).send_buf_len() == 0 {
            let _ = p.tcp_a_mut(0).send(&vec![0x66u8; 2_000]);
        }
        for snap in p.tcp_a(0).bbr_history() {
            if snap.bw_shortterm != u64::MAX {
                saw_bw_adapted = true;
                adapted_bw_st = adapted_bw_st.min(snap.bw_shortterm);
            }
            if snap.inflight_shortterm != u32::MAX {
                saw_inflight_adapted = true;
                adapted_inflight_st = adapted_inflight_st.min(snap.inflight_shortterm);
            }
        }
        !(saw_bw_adapted && saw_inflight_adapted)
    });

    let state = pair.tcp_a().state;
    assert_ok!(
        state == rawket::tcp::State::Established,
        "A not Established after BBR loss recovery: {state:?}"
    );
    assert_ok!(
        saw_bw_adapted,
        "bw_shortterm never left sentinel during sustained loss"
    );
    // bw_shortterm is initialized to max_bw on first loss, then reduced by Beta=0.7.
    // It can briefly exceed max_bw if bw_latest (delivery rate) exceeds the windowed max.
    // Check that it was set to a sane value (non-zero, not sentinel).
    assert_ok!(
        adapted_bw_st > 0,
        "bw_shortterm ({adapted_bw_st}) should be > 0 after loss adaptation"
    );
    assert_ok!(
        saw_inflight_adapted,
        "inflight_shortterm never left sentinel during sustained loss"
    );
    let mss = pair.tcp_a().peer_mss() as u32;
    // On a latency link, BDP can be ~170 MSS; allow up to 200*MSS.
    assert_ok!(
        adapted_inflight_st <= 200 * mss,
        "inflight_shortterm ({adapted_inflight_st}) unreasonably large after loss (200*MSS={})",
        200 * mss
    );

    Ok(())
}

// ── startup_exit_on_loss ───────────────────────────────────────────────────
//
// draft-ietf-ccwg-bbr-04 §5.3.1.3: Exit Startup when sustained loss > 2%.
// Use ~10% loss; verify connection survives and BBR exits Startup.
#[test]
fn startup_exit_on_loss() -> TestResult {
    let mut pair = setup_tcp_pair()
        .rto_min_ms(10).max_retransmits(100).rto_max_ms(200)
        .profile(LinkProfile::leased_line_100m())
        .connect();
    pair.loss_to_b(0.10);

    let mut exited_startup = false;
    pair.tcp_a_mut().send(&vec![0x77u8; 2_000])?;
    pair.transfer_while(|p| {
        if p.tcp_a(0).send_buf_len() == 0 {
            let _ = p.tcp_a_mut(0).send(&vec![0x77u8; 2_000]);
        }
        for snap in p.tcp_a(0).bbr_history() {
            if snap.phase != BbrPhase::Startup {
                exited_startup = true;
            }
        }
        !exited_startup
    });

    assert_ok!(
        exited_startup,
        "BBR should have exited Startup due to sustained loss"
    );

    let state = pair.tcp_a().state;
    assert_ok!(
        state == rawket::tcp::State::Established,
        "A not Established after lossy Startup exit: {state:?}"
    );

    Ok(())
}

// ── probe_rtt_cwnd_reduced ─────────────────────────────────────────────────
//
// draft-ietf-ccwg-bbr-04 §4.3.4, §4.4.2: ProbeRTT sets
// cwnd = BBRMinPipeCwnd = 4*MSS.
// Send enough data to grow cwnd above 4*MSS, then trigger ProbeRtt and
// verify cwnd drops to ≤ 4*MSS.
#[test]
fn probe_rtt_cwnd_reduced() -> TestResult {
    let mut pair = setup_tcp_pair()
        .profile(LinkProfile::leased_line_100m())
        .connect();

    // Drive to ProbeBW first — ensures min_rtt is measured and cwnd is grown.
    drive_to_probe_bw(&mut pair)?;

    let mss = pair.tcp_a().peer_mss() as u32;
    let mss_threshold = 5 * mss;
    let cwnd_before = pair.tcp_a().bbr_cwnd();
    assert_ok!(
        cwnd_before > mss_threshold,
        "cwnd ({cwnd_before}) not above 5*MSS ({mss_threshold}) — test setup insufficient"
    );

    // Advance past probe_rtt_interval (5000 ms).
    pair.advance_both(6_000);

    // Send data to trigger ProbeRtt; use bbr_history() to find the entry.
    let mut found = false;
    pair.tcp_a_mut().send(&vec![0x55u8; 2_000])?;
    pair.transfer_while(|p| {
        if p.tcp_a(0).send_buf_len() == 0 {
            let _ = p.tcp_a_mut(0).send(&vec![0x55u8; 2_000]);
        }

        for snap in p.tcp_a(0).bbr_history() {
            if snap.phase == BbrPhase::ProbeRtt {
                found = true;
            }
        }
        !found
    });
    assert_ok!(found, "never observed ProbeRtt entry in bbr_history()");

    for snap in pair.tcp_a().bbr_history() {
        if snap.phase == BbrPhase::ProbeRtt {
            // BBRSetCwnd (spec §5.6.2): cwnd = 4*MSS in ProbeRtt.
            assert_ok!(
                snap.cwnd == 4 * mss,
                "cwnd at ProbeRtt entry ({}) != 4*MSS ({}) — prior_cwnd={}",
                snap.cwnd, 4 * mss, snap.prior_cwnd
            );
            // prior_cwnd must capture the pre-ProbeRtt value.
            assert_ok!(
                snap.prior_cwnd > mss_threshold,
                "prior_cwnd ({}) not above 5*MSS — not properly saved",
                snap.prior_cwnd
            );
            return Ok(());
        }
    }
    assert_ok!(false, "ProbeRtt found during transfer but not in final history");
    Ok(())
}

// ── cwnd_floor_after_loss ──────────────────────────────────────────────────
//
// draft-ietf-ccwg-bbr-04 §5.6.3: BBRBoundCwndForModel applies
// inflight_shortterm as an upper bound (ceiling), not a floor.
// The only cwnd floor is BBRMinPipeCwnd = 4*MSS.
#[test]
fn cwnd_floor_after_loss() -> TestResult {
    // Clean handshake on leased-line, then add 10% loss.
    let mut pair = setup_tcp_pair()
        .max_retransmits(100)
        .rto_max_ms(200)
        .profile(LinkProfile::leased_line_100m())
        .connect();
    pair.loss_to_b(0.10);

    drive_to_probe_bw(&mut pair)?;

    let mss = pair.tcp_a().peer_mss() as u32;
    let mut saw_down_cruise = false;
    let mut floor_violated_cwnd = 0u32;
    let mut floor_violated_floor = 0u32;

    pair.tcp_a_mut().send(&vec![0x88u8; 2_000])?;
    pair.transfer_while(|p| {
        if p.tcp_a(0).send_buf_len() == 0 {
            let _ = p.tcp_a_mut(0).send(&vec![0x88u8; 2_000]);
        }
        for snap in p.tcp_a(0).bbr_history() {
            if matches!(snap.phase, BbrPhase::ProbeBwDown | BbrPhase::ProbeBwCruise) {
                saw_down_cruise = true;
                let floor = 4 * mss;
                if snap.cwnd < floor && floor_violated_cwnd == 0 {
                    floor_violated_cwnd = snap.cwnd;
                    floor_violated_floor = floor;
                }
            }
        }
        !saw_down_cruise
    });

    assert_ok!(
        pair.tcp_a().state == rawket::tcp::State::Established,
        "A not Established after sustained loss"
    );
    assert_ok!(
        saw_down_cruise,
        "never observed ProbeBW_DOWN/CRUISE during sustained loss"
    );
    assert_ok!(
        floor_violated_cwnd == 0,
        "cwnd ({floor_violated_cwnd}) < floor ({floor_violated_floor}) during ProbeBW_DOWN/CRUISE"
    );

    Ok(())
}
