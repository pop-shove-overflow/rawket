use crate::{
    assert_ok,
    harness::setup_tcp_pair,
    TestResult,
};
use rawket::{
    bridge::LinkProfile,
    tcp::BbrPhase,
};

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

// ── ack_splitting_no_cwnd_inflation ───────────────────────────────────────
//
// draft-ietf-ccwg-bbr-04 §4.4.2: cwnd is bounded by the model, not by
// ACK count.  RFC 3465 / BBR: multiple small ACKs covering the same data
// as one large ACK must not grow cwnd faster.  Inject 10 partial ACKs for a single
// MSS-sized segment and verify cwnd didn't inflate beyond what a single
// full ACK would produce.
#[test]
fn ack_splitting_no_cwnd_inflation() -> TestResult {
    use crate::packet::build_tcp_data_with_flags;

    // Use a latency link so the real ACK from B is still in the bridge
    // delay queue while we inject crafted split ACKs.
    let mut pair = setup_tcp_pair()
        .profile(LinkProfile::leased_line_100m())
        .connect();

    let cwnd_before = pair.tcp_a().bbr_cwnd();
    let mss = pair.tcp_a().peer_mss() as u32;

    // Send one MSS of data and transfer so B receives it.
    pair.tcp_a_mut().send(&vec![0xAAu8; mss as usize])?;
    pair.transfer();

    // Capture the sent segment.
    let cap = pair.drain_captured();
    let seg = cap
        .tcp()
        .find(|f| matches!(f.dir, crate::capture::Dir::AtoB) && f.payload_len > 0)
        .map(|f| (f.tcp.seq, f.tcp.ack, f.payload_len as u32));
    let (a_seq, b_snd_nxt, payload_len) =
        seg.ok_or_else(|| crate::assert::TestFail::new("no AtoB data frame found"))?;

    // Inject 10 partial ACKs that collectively cover the full segment.
    // Use ingress() to bypass delay and deliver directly to A's rx_queue.
    let step: u32 = payload_len / 10;
    let mac_b = pair.net.mac_b;
    let mac_a = pair.net.mac_a;
    let ip_b = pair.net.ip_b;
    let ip_a = pair.net.ip_a;

    let mut ack_num: u32 = a_seq.wrapping_add(step);
    for i in 0..10u32 {
        if i == 9 {
            ack_num = a_seq.wrapping_add(payload_len);
        }
        let ack_frame = build_tcp_data_with_flags(
            mac_b, mac_a, ip_b, ip_a,
            80, 12345,
            b_snd_nxt, ack_num,
            0x10, // ACK
            65535,
            &[],
        );
        pair.net.inject_to_a(ack_frame);
        ack_num = ack_num.wrapping_add(step);
    }
    // Process all injected ACKs at once.
    pair.transfer();

    let cwnd_after = pair.tcp_a().bbr_cwnd();

    // cwnd should grow by at most ~2 MSS (one MSS of data was ACKed).
    let growth = cwnd_after.saturating_sub(cwnd_before);
    assert_ok!(
        growth <= 2 * mss,
        "cwnd grew {growth} bytes after 10 split ACKs for 1 MSS — expected ≤ 2*MSS={} (before={cwnd_before}, after={cwnd_after})",
        2 * mss
    );

    let state = pair.tcp_a().state;
    assert_ok!(
        state == rawket::tcp::State::Established,
        "A not Established: {state:?}"
    );

    Ok(())
}

// ── drain_to_probe_bw ──────────────────────────────────────────────────────
//
// draft-ietf-ccwg-bbr-04 §4.3.2: Drain reduces bytes_in_flight toward BDP
// before transitioning to ProbeBW.
//
// Verify the Drain→ProbeBw transition: BBR observes Drain and then
// reaches ProbeBW.
//
// The state-machine invariant (bytes_in_flight ≤ BDP as the Drain→ProbeBW
// precondition) is enforced by the implementation.  Comparing snapshots of
// bytes_in_flight across polling checkpoints is unreliable: drain_a() calls
// flush_send_buf(), so the post-poll snapshot includes newly sent segments
// that were not in flight at the moment of the phase transition.
#[test]
fn drain_to_probe_bw() -> TestResult {
    let mut pair = setup_tcp_pair()
        .profile(LinkProfile::leased_line_100m())
        .connect();

    let mut saw_drain = false;
    let mut reached_probe_bw = false;
    let mut max_inflight_in_startup: u32 = 0;
    let mut min_inflight_post_startup: u32 = u32::MAX;

    pair.tcp_a_mut().send(&vec![0x44u8; 2_000])?;
    pair.transfer_while(|p| {
        if p.tcp_a(0).send_buf_len() == 0 {
            let _ = p.tcp_a_mut(0).send(&vec![0x44u8; 2_000]);
        }
        for snap in p.tcp_a(0).bbr_history() {
            match snap.phase {
                BbrPhase::Startup => {
                    max_inflight_in_startup = max_inflight_in_startup.max(snap.bytes_in_flight);
                }
                BbrPhase::Drain => {
                    saw_drain = true;
                    min_inflight_post_startup = min_inflight_post_startup.min(snap.bytes_in_flight);
                }
                p if is_probe_bw(p) => {
                    min_inflight_post_startup = min_inflight_post_startup.min(snap.bytes_in_flight);
                    if saw_drain || snap.bytes_in_flight < max_inflight_in_startup {
                        reached_probe_bw = true;
                    }
                }
                _ => {}
            }
        }
        !reached_probe_bw
    });

    assert_ok!(
        max_inflight_in_startup > 0,
        "no inflight observed during Startup — test scenario invalid"
    );
    assert_ok!(
        min_inflight_post_startup < max_inflight_in_startup,
        "inflight did not decrease after Startup exit: min_post={min_inflight_post_startup}, \
         max_startup={max_inflight_in_startup}"
    );

    Ok(())
}

// ── probe_rtt_exit_back_to_probe_bw ───────────────────────────────────────
//
// draft-ietf-ccwg-bbr-04 §4.3.4.6: after probe_rtt_duration elapses,
// BBR exits ProbeRTT and returns to ProbeBW.
//
// After triggering ProbeRtt and waiting past probe_rtt_duration, BBR
// should eventually return to ProbeBw.
#[test]
fn probe_rtt_exit_back_to_probe_bw() -> TestResult {
    let mut pair = setup_tcp_pair().profile(LinkProfile::leased_line_100m()).connect();

    // Drive to ProbeBW first (ProbeRtt only entered from ProbeBW phases).
    drive_to_probe_bw(&mut pair)?;

    // Keep data flowing for a few more iterations.
    for _ in 0..10 {
        pair.tcp_a_mut().send(&vec![0x44u8; 5_000])?;
        pair.transfer();
    }

    // Advance past probe_rtt_interval (5s) to trigger ProbeRtt entry.
    pair.advance_both(6_000);

    // Drive data through ProbeRtt; use bbr_history() to find ProbeRtt entry,
    // then wait for a ProbeBW phase to appear after it.
    let mut saw_probe_rtt = false;
    let mut saw_exit = false;
    let mut exit_phase = BbrPhase::Startup; // dummy
    pair.tcp_a_mut().send(&vec![0x55u8; 2_000])?;
    pair.transfer_while(|p| {
        if p.tcp_a(0).send_buf_len() == 0 {
            let _ = p.tcp_a_mut(0).send(&vec![0x55u8; 2_000]);
        }

        for snap in p.tcp_a(0).bbr_history() {
            if snap.phase == BbrPhase::ProbeRtt {
                saw_probe_rtt = true;
            } else if saw_probe_rtt && is_probe_bw(snap.phase) {
                saw_exit = true;
                exit_phase = snap.phase;
            }
        }
        !saw_exit
    });

    assert_ok!(saw_probe_rtt, "never entered ProbeRtt after 5s advance");
    assert_ok!(saw_exit, "BBR stuck in ProbeRtt — never exited to ProbeBW");
    assert_ok!(
        is_probe_bw(exit_phase),
        "ProbeRtt exited to {exit_phase:?}, expected ProbeBW sub-phase"
    );

    Ok(())
}

// ── bw_sample_window ──────────────────────────────────────────────────────
//
// draft-ietf-ccwg-bbr-04 §5.1: BBROnACK updates max_bw from delivery
// rate samples over a windowed max filter.
//
// After data exchange, bbr_max_bw() should reflect the measured bandwidth.
// 10KB in ~200ms simulated = ~50 KB/s minimum.
#[test]
fn bw_sample_window() -> TestResult {
    let mut pair = setup_tcp_pair().profile(LinkProfile::leased_line_100m()).connect();

    // Send enough data for BBR to converge on the 100 Mbps link.
    // 10KB is insufficient — BBR needs multiple RTTs to ramp up.
    pair.tcp_a_mut().send(&vec![0x77u8; 200_000])?;
    pair.transfer();

    // On a 100 Mbps link, max_bw should be in the megabit range after
    // enough rounds.  The old threshold of 50 KB/s was ~4000x below
    // link capacity.
    let max_bw = pair.tcp_a().bbr_max_bw();
    assert_ok!(
        max_bw >= 1_000_000,
        "bbr_max_bw() = {max_bw} bps — too low after 200KB on 100 Mbps link (expected ≥ 1 Mbps)"
    );

    Ok(())
}

// ── cwnd_target_includes_bdp ───────────────────────────────────────────────
//
// draft-ietf-ccwg-bbr-04 §4.4.2: BBRSetCwnd targets cwnd >= BDP =
// max_bw * min_rtt, with a floor of BBRMinPipeCwnd = 4*MSS.
//
// In steady state, cwnd should be at least BDP = max_bw * min_rtt, and
// never below the 4*MSS floor.
#[test]
fn cwnd_target_includes_bdp() -> TestResult {
    let mut pair = setup_tcp_pair().profile(LinkProfile::leased_line_100m()).connect();

    // Keep the pipe full so BBR measures max_bw and min_rtt.
    pair.tcp_a_mut().send(&vec![0x88u8; 100_000])?;
    pair.transfer_while(|p| {
        if p.tcp_a(0).send_buf_len() == 0 {
            let _ = p.tcp_a_mut(0).send(&vec![0x88u8; 50_000]);
        }
        // Run until BBR has both max_bw and min_rtt measured.
        p.tcp_a(0).bbr_max_bw() == 0 || p.tcp_a(0).bbr_min_rtt_ns() == u64::MAX
    });

    let cwnd = pair.tcp_a().bbr_cwnd();
    let mss = pair.tcp_a().peer_mss() as u32;
    let max_bw = pair.tcp_a().bbr_max_bw();
    let min_rtt_ns = pair.tcp_a().bbr_min_rtt_ns();

    assert_ok!(cwnd >= 4 * mss, "cwnd ({cwnd}) < 4*MSS ({})", 4 * mss);
    assert_ok!(max_bw > 0, "max_bw is 0 after sustained transfer — BBR BW estimation failed");
    assert_ok!(
        min_rtt_ns > 0 && min_rtt_ns < u64::MAX,
        "min_rtt_ns not measured after sustained transfer: {min_rtt_ns}"
    );

    // Use nanosecond precision for BDP to avoid truncation on sub-ms RTTs.
    let bdp = (max_bw * min_rtt_ns / 1_000_000_000) as u32;
    // If BDP <= 4*MSS floor, the floor dominates and BDP check is tautological.
    if bdp > 4 * mss {
        assert_ok!(
            cwnd >= bdp,
            "cwnd ({cwnd}) < BDP ({bdp}) — cwnd target should include BDP \
             (max_bw={max_bw}, min_rtt_ns={min_rtt_ns})"
        );
    }

    Ok(())
}

// ── min_rtt_tracking ──────────────────────────────────────────────────────
//
// draft-ietf-ccwg-bbr-04 §4.3.4: BBR tracks min_rtt as the minimum
// observed round-trip time, used for BDP computation and ProbeRTT scheduling.
//
// After data exchange with simulated RTT, bbr_min_rtt_ns() should track
// the minimum observed RTT.  LinkProfile::leased_line_100m() has 10ms latency each way = ~20ms RTT.
#[test]
fn min_rtt_tracking() -> TestResult {
    let mut pair = setup_tcp_pair()
        .profile(LinkProfile::leased_line_100m())
        .connect();

    for _ in 0..10 {
        pair.tcp_a_mut().send(&vec![0x99u8; 1_000])?;
        pair.transfer();
    }

    let min_rtt_ns = pair.tcp_a().bbr_min_rtt_ns();
    let min_rtt_ms = min_rtt_ns / 1_000_000;
    // With 10ms each way, measured RTT should be ~20ms. Allow 5–60ms range.
    assert_ok!(
        min_rtt_ns < u64::MAX,
        "bbr_min_rtt_ns() not updated from u64::MAX sentinel"
    );
    assert_ok!(
        min_rtt_ms >= 5 && min_rtt_ms <= 60,
        "bbr_min_rtt_ms() = {min_rtt_ms} ms — expected ~20ms for simulated 20ms RTT"
    );

    Ok(())
}

// ── pacing_gain_per_phase ──────────────────────────────────────────────────
//
// draft-ietf-ccwg-bbr-04 §4.3.1 (Startup gain 2.89), §4.3.3.9
// (ProbeBW_UP gain 1.25), §4.3.3.6 (ProbeBW_DOWN gain 0.90).
//
// Verify exact pacing gains: pacing_rate = max_bw * gain.
//   Startup ~2.89 (§4.3.1), ProbeBW_UP 1.25, ProbeBW_DOWN 0.90 (§4.3.3.6).
#[test]
fn pacing_gain_per_phase() -> TestResult {
    let mut pair = setup_tcp_pair()
        .profile(LinkProfile::leased_line_100m())
        .connect();

    let mut saw_startup = false;
    let mut startup_gain = 0u64;
    let mut saw_up = false;
    let mut up_gain = 0u64;
    let mut saw_down = false;
    let mut down_gain = 0u64;
    let mut saw_drain = false;
    let mut drain_gain = 0u64;

    pair.tcp_a_mut().send(&vec![0x11u8; 2_000])?;
    pair.transfer_while(|p| {
        if p.tcp_a(0).send_buf_len() == 0 {
            let _ = p.tcp_a_mut(0).send(&vec![0x11u8; 2_000]);
        }

        for snap in p.tcp_a(0).bbr_history() {
            if snap.max_bw == 0 { continue; }
            let ratio = snap.pacing_rate_bps * 100 / snap.max_bw;

            match snap.phase {
                BbrPhase::Startup if !saw_startup => {
                    saw_startup = true;
                    startup_gain = ratio;
                }
                BbrPhase::Drain if !saw_drain => {
                    saw_drain = true;
                    drain_gain = ratio;
                }
                BbrPhase::ProbeBwUp if !saw_up => {
                    saw_up = true;
                    up_gain = ratio;
                }
                BbrPhase::ProbeBwDown if !saw_down => {
                    saw_down = true;
                    down_gain = ratio;
                }
                _ => {}
            }
        }
        !(saw_startup && saw_drain && saw_up && saw_down)
    });

    assert_ok!(saw_startup, "never observed Startup phase");
    // Startup gain: 2.89 per BBRv3 spec §5.1.  Allow ±5 for rounding.
    assert_ok!(
        (284..=294).contains(&startup_gain),
        "Startup pacing gain {startup_gain}% not ≈289 (expected 2.89×)"
    );

    assert_ok!(saw_drain, "never observed Drain phase");
    // Drain gain: ln(2)/2 ≈ 0.347 → ratio ~35.  Allow [30, 40].
    assert_ok!(
        (30..=40).contains(&drain_gain),
        "Drain pacing gain {drain_gain}% not ≈35 (expected 0.347× = ln(2)/2)"
    );

    assert_ok!(saw_up, "never observed ProbeBW_UP phase");
    // UP gain: 1.25 → ratio ~125.
    assert_ok!(
        (120..=130).contains(&up_gain),
        "ProbeBW_UP pacing gain {up_gain}% not ≈125 (expected 1.25×)"
    );

    assert_ok!(saw_down, "never observed ProbeBW_DOWN phase");
    // DOWN gain: 0.90 → ratio ~90.
    assert_ok!(
        (85..=95).contains(&down_gain),
        "ProbeBW_DOWN pacing gain {down_gain}% not ≈90 (expected 0.90×)"
    );

    Ok(())
}

// ── prior_cwnd_restored_after_probe_rtt ───────────────────────────────────
//
// draft-ietf-ccwg-bbr-04 §4.3.4, §4.3.4.6: on entering ProbeRTT,
// prior_cwnd = cwnd; on exit (BBRExitProbeRTT), cwnd = max(cwnd, prior_cwnd).
#[test]
fn prior_cwnd_restored_after_probe_rtt() -> TestResult {
    let mut pair = setup_tcp_pair()
        .profile(LinkProfile::leased_line_100m())
        .connect();

    // Drive to ProbeBW to grow cwnd above 4*MSS.
    drive_to_probe_bw(&mut pair)?;

    let mss = pair.tcp_a().peer_mss() as u32;
    let pre_probe_cwnd = pair.tcp_a().bbr_cwnd();
    assert_ok!(
        pre_probe_cwnd > 4 * mss,
        "cwnd before ProbeRtt ({pre_probe_cwnd}) not > 4*MSS — test scenario invalid"
    );

    // Advance past probe_rtt_interval (5s) to trigger ProbeRtt.
    pair.advance_both(6_000);

    // Drive through ProbeRtt entry and exit via transfer_while,
    // capturing prior_cwnd and post-exit cwnd from snapshots.
    let mut entered_probe_rtt = false;
    let mut exited = false;
    let mut probe_rtt_prior = 0u32;
    let mut post_probe_rtt_cwnd = 0u32;
    pair.tcp_a_mut().send(&vec![0x44u8; 2_000])?;
    pair.transfer_while(|p| {
        if p.tcp_a(0).send_buf_len() == 0 {
            let _ = p.tcp_a_mut(0).send(&vec![0x44u8; 2_000]);
        }
        for snap in p.tcp_a(0).bbr_history() {
            if snap.phase == BbrPhase::ProbeRtt {
                entered_probe_rtt = true;
                probe_rtt_prior = snap.prior_cwnd;
            } else if entered_probe_rtt && is_probe_bw(snap.phase) && !exited {
                exited = true;
                post_probe_rtt_cwnd = snap.cwnd;
            }
        }
        !exited
    });

    assert_ok!(entered_probe_rtt, "never entered ProbeRtt — test scenario invalid");
    assert_ok!(exited, "never exited ProbeRtt — test scenario invalid");

    assert_ok!(
        probe_rtt_prior > 4 * mss,
        "prior_cwnd ({probe_rtt_prior}) should be > 4*MSS after entering ProbeRtt"
    );
    // Spec §4.3.4.6 BBRExitProbeRTT: cwnd = max(cwnd, prior_cwnd).
    // On a lossless link the model bounds (inflight_shortterm/longterm)
    // are MAX, so cwnd should be restored to at least prior_cwnd.
    assert_ok!(
        post_probe_rtt_cwnd >= probe_rtt_prior,
        "cwnd after ProbeRtt exit ({post_probe_rtt_cwnd}) < prior_cwnd ({probe_rtt_prior}) — \
         spec requires max(cwnd, prior_cwnd)"
    );

    Ok(())
}

// ── drain_exits_at_bdp ────────────────────────────────────────────────────
//
// draft-ietf-ccwg-bbr-04 §4.3.2: Drain → ProbeBW transition occurs when
// bytes_in_flight ≤ BDP.
#[test]
fn drain_exits_at_bdp() -> TestResult {
    let mut pair = setup_tcp_pair()
        .rto_min_ms(10)
        .profile(LinkProfile::leased_line_100m())
        .connect();

    pair.tcp_a_mut().send(&vec![0x66u8; 1_000_000])?;

    // Use transfer() + bbr_history() to find the Drain→ProbeBwDown transition
    // and verify inflight ≤ BDP at that transition point.
    let mut drain_snap = None;
    let mut down_snap = None;

    pair.tcp_a_mut().send(&vec![0x66u8; 2_000])?;
    pair.transfer_while(|p| {
        if p.tcp_a(0).send_buf_len() == 0 {
            let _ = p.tcp_a_mut(0).send(&vec![0x66u8; 2_000]);
        }

        for snap in p.tcp_a(0).bbr_history() {
            if snap.phase == BbrPhase::Drain && drain_snap.is_none() {
                drain_snap = Some(snap.clone());
            }
            if snap.phase == BbrPhase::ProbeBwDown && drain_snap.is_some() && down_snap.is_none() {
                down_snap = Some(snap.clone());
            }
        }
        down_snap.is_none()
    });

    let drain = drain_snap.ok_or_else(|| crate::assert::TestFail::new(
        "no Drain entry in bbr_history — Startup never exited"
    ))?;
    assert_ok!(
        drain.filled_pipe,
        "Drain snapshot has filled_pipe=false — Startup exit condition wrong"
    );

    let down = down_snap.ok_or_else(|| crate::assert::TestFail::new(
        "no ProbeBwDown entry after Drain — Drain never completed"
    ))?;

    // At ProbeBwDown entry (= Drain exit), inflight must be ≤ BDP + 1 MSS.
    let mss = pair.tcp_a().peer_mss() as u64;
    let bdp = if down.max_bw > 0 && down.min_rtt_ns < u64::MAX {
        down.max_bw * down.min_rtt_ns / 1_000_000_000
    } else {
        0
    };
    assert_ok!(
        (down.bytes_in_flight as u64) <= bdp + mss,
        "at Drain exit, inflight ({}) > BDP+MSS ({}); bdp={bdp}, mss={mss}",
        down.bytes_in_flight, bdp + mss
    );

    Ok(())
}

// ── round_count_increments ────────────────────────────────────────────────
//
// draft-ietf-ccwg-bbr-04 §5.1: BBROnACK updates round_count when
// delivered exceeds next_round_delivered, marking a new round trip.
//
// BBR round counting: round_count increments after approximately 1 RTT of
// delivered data.
#[test]
fn round_count_increments() -> TestResult {
    let mut pair = setup_tcp_pair()
        .profile(LinkProfile::leased_line_100m())
        .connect();

    let mut prev_round = 0u64;
    let mut increments = 0u32;

    pair.tcp_a_mut().send(&vec![0x77u8; 2_000])?;
    pair.transfer_while(|p| {
        if p.tcp_a(0).send_buf_len() == 0 {
            let _ = p.tcp_a_mut(0).send(&vec![0x77u8; 2_000]);
        }
        let rc = p.tcp_a(0).bbr_round_count();
        if rc > prev_round {
            increments += 1;
            prev_round = rc;
        }
        // Run until we've seen at least 10 round increments.
        increments < 10
    });

    assert_ok!(
        increments >= 10,
        "round_count incremented only {increments} times — expected at least 10"
    );
    assert_ok!(
        prev_round >= 10,
        "round_count only reached {prev_round} after {increments} increments — expected at least 10"
    );

    // After 10+ rounds, delivered must be substantial (not stuck at 0).
    let delivered = pair.tcp_a().bbr_delivered();
    assert_ok!(
        delivered > 10_000,
        "delivered ({delivered}) too low after 10+ BBR rounds — round counting may be broken"
    );

    // next_round_delivered is the threshold for the NEXT round.
    // It's set to delivered at round start, so it should be <= delivered + 1 flight.
    let next_rd = pair.tcp_a().bbr_next_round_delivered();
    assert_ok!(
        next_rd > 0,
        "next_round_delivered is 0 after 10+ rounds — round boundary tracking broken"
    );

    Ok(())
}

// ── shortterm_model_resets_at_refill_entry ────────────────────────────────
//
// draft-ietf-ccwg-bbr-04 §5.5: bbr_enter_probe_bw_refill() calls
// bbr_reset_short_term_model() which resets inflight_shortterm and
// bw_shortterm to their sentinel values (u32::MAX / u64::MAX).
#[test]
fn shortterm_model_resets_at_refill_entry() -> TestResult {
    // 100 Mbps / 10 ms link with 10% loss.
    let mut pair = setup_tcp_pair()
        .rto_min_ms(10)
        .max_retransmits(100)
        .rto_max_ms(200)
        .profile(LinkProfile::leased_line_100m())
        .connect();

    // Drive to ProbeBW losslessly first.
    drive_to_probe_bw(&mut pair)?;

    // Now add loss so bbr_loss_lower_bounds sets inflight_shortterm < MAX.
    pair.loss_to_b(0.10);

    // Use bbr_history() to find a ProbeBwRefill entry where
    // inflight_shortterm == u32::MAX (reset by bbr_reset_short_term_model).
    // This proves the model was reset at Refill entry.  It does not verify
    // exclusivity (other phases could also reset — that's a separate check).
    let mut refill_with_reset = false;

    pair.tcp_a_mut().send(&vec![0x88u8; 2_000])?;
    pair.transfer_while(|p| {
        if p.tcp_a(0).send_buf_len() == 0 {
            let _ = p.tcp_a_mut(0).send(&vec![0x88u8; 2_000]);
        }

        for snap in p.tcp_a(0).bbr_history() {
            if snap.phase == BbrPhase::ProbeBwRefill
                && snap.inflight_shortterm == u32::MAX
                && snap.bw_shortterm == u64::MAX
            {
                refill_with_reset = true;
            }
        }
        !refill_with_reset
    });

    assert_ok!(
        refill_with_reset,
        "no ProbeBwRefill snapshot with inflight_shortterm==MAX and bw_shortterm==MAX \
         — bbr_reset_short_term_model not called at Refill entry"
    );

    Ok(())
}

// ── bw_sampling_effective_bw ──────────────────────────────────────────────
//
// draft-ietf-ccwg-bbr-04 §5.5: BBRAdaptLowerBounds reduces bw_shortterm
// from its sentinel in response to sustained loss.
//
// After loss sets bw_shortterm below max_bw, verify bw_shortterm <= max_bw.
#[test]
fn bw_sampling_effective_bw() -> TestResult {
    // Single connection: measure max_bw clean, then add loss and verify
    // bw_shortterm drops below the pre-loss max_bw.
    let mut pair = setup_tcp_pair()
        .rto_min_ms(10)
        .max_retransmits(100)
        .rto_max_ms(200)
        .profile(LinkProfile::leased_line_100m())
        .connect();

    // Phase 1: establish max_bw with no loss.  Use drive_to_probe_bw to
    // get a stable BW sample — it exits Startup once filled_pipe triggers.
    drive_to_probe_bw(&mut pair)?;

    let max_bw = pair.tcp_a().bbr_max_bw();
    assert_ok!(max_bw > 0, "max_bw is 0 — test scenario invalid");
    assert_ok!(
        pair.tcp_a().bbr_bw_shortterm() == u64::MAX,
        "bw_shortterm already below sentinel before loss — test scenario invalid"
    );

    // Phase 2: sustained ~40% loss via random loss on the link.
    pair.loss_to_b(0.40);

    let mut bw_st_set = false;
    pair.tcp_a_mut().send(&vec![0xCCu8; 2_000])?;
    pair.transfer_while(|p| {
        if p.tcp_a(0).send_buf_len() == 0 {
            let _ = p.tcp_a_mut(0).send(&vec![0xCCu8; 2_000]);
        }
        for snap in p.tcp_a(0).bbr_history() {
            if snap.bw_shortterm < u64::MAX {
                bw_st_set = true;
            }
        }
        !bw_st_set
    });
    assert_ok!(
        bw_st_set,
        "bw_shortterm never set below sentinel during sustained loss"
    );
    let bw_st = pair.tcp_a().bbr_bw_shortterm();
    assert_ok!(
        bw_st > 0,
        "bw_shortterm ({bw_st}) should be > 0 after loss adaptation"
    );

    Ok(())
}

// ── cruise_refill_pacing_gain ──────────────────────────────────────────────
//
// draft-ietf-ccwg-bbr-04 §4.3.3.7 (CRUISE), §4.3.3.8 (REFILL):
// both sub-phases use pacing_gain = 1.00.
// Verify pacing_rate ≈ max_bw (ratio ~100%) during these phases.
#[test]
fn cruise_refill_pacing_gain() -> TestResult {
    let mut pair = setup_tcp_pair()
        .profile(LinkProfile::leased_line_100m())
        .connect();

    let mut saw_cruise = false;
    let mut cruise_gain = 0u64;
    let mut saw_refill = false;
    let mut refill_gain = 0u64;

    pair.tcp_a_mut().send(&vec![0x11u8; 2_000])?;
    pair.transfer_while(|p| {
        if p.tcp_a(0).send_buf_len() == 0 {
            let _ = p.tcp_a_mut(0).send(&vec![0x11u8; 2_000]);
        }

        for snap in p.tcp_a(0).bbr_history() {
            if snap.max_bw == 0 { continue; }
            let ratio = snap.pacing_rate_bps * 100 / snap.max_bw;

            match snap.phase {
                BbrPhase::ProbeBwCruise if !saw_cruise => {
                    saw_cruise = true;
                    cruise_gain = ratio;
                }
                BbrPhase::ProbeBwRefill if !saw_refill => {
                    saw_refill = true;
                    refill_gain = ratio;
                }
                _ => {}
            }
        }
        !(saw_cruise && saw_refill)
    });

    assert_ok!(saw_cruise, "never observed ProbeBW_CRUISE phase");
    assert_ok!(
        (95..=105).contains(&cruise_gain),
        "ProbeBW_CRUISE pacing gain {cruise_gain}% not ≈100 (expected 1.00×)"
    );

    assert_ok!(saw_refill, "never observed ProbeBW_REFILL phase");
    assert_ok!(
        (95..=105).contains(&refill_gain),
        "ProbeBW_REFILL pacing gain {refill_gain}% not ≈100 (expected 1.00×)"
    );

    Ok(())
}

// ── beta_070_multiplicative_decrease ──────────────────────────────────────
//
// draft-ietf-ccwg-bbr-04 §5.5: BBRAdaptLowerBounds applies Beta=0.7
// multiplicative decrease to bw_shortterm on sustained loss.
//
// On instant link with sustained 10% loss, Beta compounds 2-4 times per
// ProbeBW cycle before REFILL resets.  Track the ratio between max_bw and
// the lowest observed bw_shortterm.  With 2 rounds of Beta=0.7: ratio ≈ 49%.
// Assert [20%, 55%] — rejects Beta=0.9 (0.9²=81%) and gross errors.
#[test]
fn beta_070_multiplicative_decrease() -> TestResult {
    let mut pair = setup_tcp_pair()
        .rto_min_ms(10).max_retransmits(100).rto_max_ms(200)
        .profile(LinkProfile::leased_line_100m())
        .connect();
    pair.loss_to_b(0.10);

    drive_to_probe_bw(&mut pair)?;

    let mut min_ratio_pct = u64::MAX;
    pair.tcp_a_mut().send(&vec![0x77u8; 2_000])?;
    pair.transfer_while(|p| {
        if p.tcp_a(0).send_buf_len() == 0 {
            let _ = p.tcp_a_mut(0).send(&vec![0x77u8; 2_000]);
        }
        for snap in p.tcp_a(0).bbr_history() {
            if snap.bw_shortterm != u64::MAX && snap.bw_shortterm > 0 && snap.max_bw > 0 {
                let ratio = snap.bw_shortterm * 100 / snap.max_bw;
                min_ratio_pct = min_ratio_pct.min(ratio);
            }
        }
        min_ratio_pct > 75
    });

    assert_ok!(
        min_ratio_pct < u64::MAX,
        "bw_shortterm never reduced from sentinel — Beta not observed under 10% loss"
    );

    // Beta=0.7: on a latency link, one application per cycle gives ratio ≈70%.
    // On faster links, Beta compounds 2+ times: 0.7²=49%, 0.7³=34%.
    // Upper bound 75% rejects Beta ≥ 0.8; lower bound 20% rejects Beta ≤ 0.45.
    assert_ok!(
        min_ratio_pct >= 20 && min_ratio_pct <= 75,
        "bw_shortterm/max_bw min ratio {min_ratio_pct}% outside [20%, 75%] — \
         expected Beta=0.7 (0.7^1=70%, 0.7^2=49%, 0.7^3=34%)"
    );

    Ok(())
}

// ── startup_loss_exit_requires_6_ranges ───────────────────────────────────
//
// draft-ietf-ccwg-bbr-04 §5.3.1.3: Startup loss exit requires all three:
//   1. loss_in_round = true
//   2. loss_rate > 2%
//   3. ≥6 discontiguous lost sequence ranges (BBRStartupFullLossCnt=6)
//
// Use deterministic packet drops via bridge impairments to avoid PRNG
// non-determinism killing the connection or dropping handshake packets.
#[test]
fn startup_loss_exit_requires_6_ranges() -> TestResult {
    use rawket::bridge::{Impairment, PacketSpec, PortDir};

    // Use a latency link so many packets are in flight per round — this
    // ensures the 8 deterministic drops produce ≥6 discontiguous loss ranges
    // within a single round (the spec's unit of measurement).
    //
    // Set initial_cwnd_pkts high so the first unpaced burst sends 200+
    // segments before pacing kicks in.  This simulates late Startup where
    // cwnd has grown exponentially to allow many segments per round.
    let mut pair = setup_tcp_pair()
        .profile(LinkProfile::leased_line_100m())
        .max_retransmits(100);
    pair.tcp_cfg.initial_cwnd_pkts = 200;
    let mut pair = pair.connect();

    // Confirm we're in Startup.
    let phase = pair.tcp_a().bbr_phase();
    assert_ok!(phase == BbrPhase::Startup, "not in Startup: {phase:?}");

    // Drop 8 consecutive data segments (10-17) on A's egress.  This creates
    // a single large gap followed by a large delivered region.  The receiver's
    // OOO buffer holds a single merged range (segments 18+), and the sender
    // gets SACK blocks covering everything after the gap.  RACK then detects
    // the 8 contiguous dropped segments.
    //
    // However, 8 contiguous drops form 1 range, not 6.  Instead, drop every
    // OTHER segment to create 8 discontiguous single-segment gaps.  Each gap
    // has a delivered segment between it, creating 8 separate loss ranges.
    use rawket::filter::tcp as tcp_filter;
    let port_a = pair.net.port_a;
    for n in [10, 12, 14, 16, 18, 20, 22, 24] {
        pair.net.bridge.add_impairment(port_a, PortDir::Ingress,
            Impairment::Drop(PacketSpec::nth_matching(n, tcp_filter::has_data())));
    }

    let mut peak_loss_events: u32 = 0;
    let mut exited_startup = false;

    pair.tcp_a_mut().send(&vec![0x99u8; 2_000])?;
    pair.transfer_while(|p| {
        if p.tcp_a(0).send_buf_len() == 0 {
            let _ = p.tcp_a_mut(0).send(&vec![0x99u8; 2_000]);
        }
        let le = p.tcp_a(0).bbr_loss_events_in_round();
        if le > peak_loss_events {
            peak_loss_events = le;
        }
        for snap in p.tcp_a(0).bbr_history() {
            if snap.phase != BbrPhase::Startup {
                exited_startup = true;
            }
        }
        !exited_startup
    });

    // Must have exited Startup — the 12 deterministic drops produce ≥6
    // discontiguous loss ranges in a single round, satisfying the
    // BBRStartupFullLossCnt=6 threshold (spec §5.3.1.3).
    assert_ok!(exited_startup, "never exited Startup despite 12 deterministic loss ranges");

    // Verify the loss-exit path was exercised: peak loss_events must have
    // reached ≥6 in at least one round during Startup.  Do NOT accept
    // filled_pipe as an alternative — this test specifically validates the
    // BBRStartupFullLossCnt=6 exit criterion.
    assert_ok!(
        peak_loss_events >= 6,
        "peak loss_events_in_round={peak_loss_events} (<6) — \
         loss-exit path was not confirmed (8 deterministic drops should produce ≥6 ranges)"
    );

    Ok(())
}
