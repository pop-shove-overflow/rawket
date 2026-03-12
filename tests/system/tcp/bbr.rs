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
