use crate::{
    assert_ok,
    harness::{fast_tcp_cfg, setup_tcp_pair},
    TestResult,
};
use rawket::{
    bridge::{reseed_prng, LinkProfile},
    tcp::{BbrPhase, TcpConfig},
};

fn broadband_link() -> LinkProfile {
    LinkProfile::leased_line_100m()
}

fn lossy_instant() -> LinkProfile {
    LinkProfile::instant().loss_to_b(0.10)
}

fn broadband_lossy() -> LinkProfile {
    LinkProfile::leased_line_100m().loss_to_b(0.10)
}

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
// Track bbr_phase() during a 1MiB transfer and verify we observe
// Startup → Drain → ProbeBw transitions.
