// Assertion helpers for system test scenarios.
#![allow(dead_code)]
use rawket::tcp::{TcpError, TcpFlags, State, TcpSocket};
use crate::capture::{CaptureBuffer, Dir, ParsedFrame, ParsedFrameExt};

// ── TestFail ──────────────────────────────────────────────────────────────────

#[derive(Debug)]
pub struct TestFail {
    pub msg: String,
}

impl TestFail {
    pub fn new(msg: impl Into<String>) -> Self {
        TestFail { msg: msg.into() }
    }
}

pub type AssertResult = Result<(), TestFail>;

impl From<rawket::Error> for TestFail {
    fn from(e: rawket::Error) -> Self {
        TestFail::new(format!("{e:?}"))
    }
}

// ── Macros ────────────────────────────────────────────────────────────────────

/// Assert a condition or return `TestFail` with a formatted message.
#[macro_export]
macro_rules! assert_ok {
    ($cond:expr, $($arg:tt)*) => {
        if !($cond) {
            return Err($crate::assert::TestFail::new(format!($($arg)*)));
        }
    };
}

// ── Frame-level assertions ────────────────────────────────────────────────────

pub fn assert_flags(frame: &ParsedFrame, want: TcpFlags, label: &str) -> AssertResult {
    let got = frame.tcp.flags;
    if !got.has(want) {
        return Err(TestFail::new(format!(
            "{label}: expected flags {want:?} but got {got:?}"
        )));
    }
    Ok(())
}

pub fn assert_flags_exact(frame: &ParsedFrame, want: TcpFlags, label: &str) -> AssertResult {
    let got = frame.tcp.flags;
    if got != want {
        return Err(TestFail::new(format!(
            "{label}: expected exact flags {want:?} but got {got:?}"
        )));
    }
    Ok(())
}

pub fn assert_seq(frame: &ParsedFrame, want: u32, label: &str) -> AssertResult {
    if frame.tcp.seq != want {
        return Err(TestFail::new(format!(
            "{label}: expected seq={want} but got {}", frame.tcp.seq
        )));
    }
    Ok(())
}

pub fn assert_ack(frame: &ParsedFrame, want: u32, label: &str) -> AssertResult {
    if frame.tcp.ack != want {
        return Err(TestFail::new(format!(
            "{label}: expected ack={want} but got {}", frame.tcp.ack
        )));
    }
    Ok(())
}

pub fn assert_payload_len(frame: &ParsedFrame, want: usize, label: &str) -> AssertResult {
    if frame.payload_len != want {
        return Err(TestFail::new(format!(
            "{label}: expected payload_len={want} but got {}", frame.payload_len
        )));
    }
    Ok(())
}

pub fn assert_payload_len_range(
    frame:  &ParsedFrame,
    min:    usize,
    max:    usize,
    label:  &str,
) -> AssertResult {
    if frame.payload_len < min || frame.payload_len > max {
        return Err(TestFail::new(format!(
            "{label}: expected payload_len in [{min},{max}] but got {}", frame.payload_len
        )));
    }
    Ok(())
}

pub fn assert_no_payload(frame: &ParsedFrame, label: &str) -> AssertResult {
    assert_payload_len(frame, 0, label)
}

// ── Option assertions ─────────────────────────────────────────────────────────

pub fn assert_mss_option(frame: &ParsedFrame, want: u16, label: &str) -> AssertResult {
    match frame.tcp.opts.mss {
        None => Err(TestFail::new(format!("{label}: MSS option absent"))),
        Some(v) if v != want => Err(TestFail::new(format!(
            "{label}: expected MSS={want} but got {v}"
        ))),
        _ => Ok(()),
    }
}

pub fn assert_mss_option_at_most(frame: &ParsedFrame, max: u16, label: &str) -> AssertResult {
    match frame.tcp.opts.mss {
        None => Err(TestFail::new(format!("{label}: MSS option absent"))),
        Some(v) if v > max => Err(TestFail::new(format!(
            "{label}: expected MSS≤{max} but got {v}"
        ))),
        _ => Ok(()),
    }
}

pub fn assert_window_scale(frame: &ParsedFrame, want: u8, label: &str) -> AssertResult {
    match frame.tcp.opts.window_scale {
        None => Err(TestFail::new(format!("{label}: WS option absent"))),
        Some(v) if v != want => Err(TestFail::new(format!(
            "{label}: expected WS={want} but got {v}"
        ))),
        _ => Ok(()),
    }
}

pub fn assert_sack_permitted(frame: &ParsedFrame, label: &str) -> AssertResult {
    if !frame.tcp.opts.sack_permitted {
        return Err(TestFail::new(format!("{label}: SACK-Permitted option absent")));
    }
    Ok(())
}

pub fn assert_timestamps_present(frame: &ParsedFrame, label: &str) -> AssertResult {
    if frame.tcp.opts.timestamps.is_none() {
        return Err(TestFail::new(format!("{label}: Timestamps option absent")));
    }
    Ok(())
}

pub fn assert_timestamps_absent(frame: &ParsedFrame, label: &str) -> AssertResult {
    if frame.tcp.opts.timestamps.is_some() {
        return Err(TestFail::new(format!("{label}: Timestamps option present but should be absent")));
    }
    Ok(())
}

/// Assert the TSecr in frame's TS option equals `want_tsecr`.
pub fn assert_tsecr(frame: &ParsedFrame, want_tsecr: u32, label: &str) -> AssertResult {
    match frame.tcp.opts.timestamps {
        None => Err(TestFail::new(format!("{label}: Timestamps option absent"))),
        Some((_, tsecr)) if tsecr != want_tsecr => Err(TestFail::new(format!(
            "{label}: expected TSecr={want_tsecr} but got {tsecr}"
        ))),
        _ => Ok(()),
    }
}

// ── SACK assertions ───────────────────────────────────────────────────────────

/// Assert SACK blocks match exactly (order-independent).
pub fn assert_sack_blocks(
    frame:    &ParsedFrame,
    expected: &[(u32, u32)],
    label:    &str,
) -> AssertResult {
    let got = &frame.tcp.opts.sack_blocks;
    let mut got_sorted  = got.to_vec();
    let mut want_sorted = expected.to_vec();
    got_sorted.sort();
    want_sorted.sort();
    if got_sorted != want_sorted {
        return Err(TestFail::new(format!(
            "{label}: expected SACK blocks {want_sorted:?} but got {got_sorted:?}"
        )));
    }
    Ok(())
}

/// Assert the first SACK block is a D-SACK (left < ack_num).
pub fn assert_dsack(frame: &ParsedFrame, label: &str) -> AssertResult {
    match frame.tcp.opts.sack_blocks.first() {
        None => Err(TestFail::new(format!("{label}: no SACK blocks"))),
        Some(&(left, _)) => {
            if left.wrapping_sub(frame.tcp.ack) < (1u32 << 31) {
                // left < ack (using sequence number arithmetic)
                return Err(TestFail::new(format!(
                    "{label}: first SACK block left={left} is not < ack={}", frame.tcp.ack
                )));
            }
            Ok(())
        }
    }
}

// ── ECN assertions ────────────────────────────────────────────────────────────

pub fn assert_ece(frame: &ParsedFrame, label: &str) -> AssertResult {
    if !frame.tcp.flags.has(TcpFlags::ECE) {
        return Err(TestFail::new(format!("{label}: ECE flag not set")));
    }
    Ok(())
}

pub fn assert_cwr(frame: &ParsedFrame, label: &str) -> AssertResult {
    if !frame.tcp.flags.has(TcpFlags::CWR) {
        return Err(TestFail::new(format!("{label}: CWR flag not set")));
    }
    Ok(())
}

pub fn assert_ect0(frame: &ParsedFrame, label: &str) -> AssertResult {
    if frame.ip_ecn != etherparse::IpEcn::Ect0 {
        return Err(TestFail::new(format!("{label}: ECT(0) bit not set in IP header")));
    }
    Ok(())
}

pub fn assert_ce(frame: &ParsedFrame, label: &str) -> AssertResult {
    if frame.ip_ecn != etherparse::IpEcn::CongestionExperienced {
        return Err(TestFail::new(format!("{label}: CE bit not set in IP header")));
    }
    Ok(())
}

// ── Timing assertions ─────────────────────────────────────────────────────────

/// Assert `|actual - expected| ≤ expected × pct / 100`.
///
/// `t1` and `t2` are nanosecond timestamps (e.g. from `CapturedFrame::ts_ns`
/// or `ParsedFrame::ts_ns`).  `expected_ms` is in milliseconds.
pub fn assert_gap_approx(
    t1:          u64,
    t2:          u64,
    expected_ms: u64,
    pct:         u64,
    label:       &str,
) -> AssertResult {
    let actual_ms = t2.saturating_sub(t1) / 1_000_000;
    let tol = expected_ms * pct / 100;
    if actual_ms.abs_diff(expected_ms) > tol {
        return Err(TestFail::new(format!(
            "{label}: expected gap≈{expected_ms}ms (±{pct}%) but got {actual_ms}ms"
        )));
    }
    Ok(())
}

// ── Capture-level assertions ──────────────────────────────────────────────────

/// Assert that exactly `want` SYN frames are present in the capture.
pub fn assert_syn_count(cap: &CaptureBuffer, want: usize, label: &str) -> AssertResult {
    let got = cap.tcp().with_tcp_flags(TcpFlags::SYN).count();
    if got != want {
        return Err(TestFail::new(format!(
            "{label}: expected {want} SYN frames but found {got}"
        )));
    }
    Ok(())
}

/// Assert that at least one FIN frame is present.
pub fn assert_fin_present(cap: &CaptureBuffer, dir: Dir, label: &str) -> AssertResult {
    if !cap.tcp().with_tcp_flags(TcpFlags::FIN).any(|f| f.dir == dir) {
        return Err(TestFail::new(format!("{label}: no FIN frame found from {dir:?}")));
    }
    Ok(())
}

/// Assert no data segments (frames with payload > 0) appear after the first
/// FIN from the given direction.
pub fn assert_no_data_after_fin(cap: &CaptureBuffer, dir: Dir, label: &str) -> AssertResult {
    let fin_ts = cap.frames()
        .direction(dir)
        .with_tcp_flags(TcpFlags::FIN)
        .map(|f| f.ts_ns)
        .next();

    if let Some(fin_ts) = fin_ts {
        for f in cap.frames().direction(dir).with_data() {
            if f.ts_ns > fin_ts {
                return Err(TestFail::new(format!(
                    "{label}: data segment after FIN at ts={}", f.ts_ns
                )));
            }
        }
    }
    Ok(())
}

/// Assert the TIME_WAIT interval is at least `min_ms`.
///
/// Measures the gap between the last FIN from `active_close_dir` and the
/// next frame (if any) from the same direction.
pub fn assert_time_wait_at_least(
    cap:             &CaptureBuffer,
    active_close_dir: Dir,
    min_ms:          u64,
    label:           &str,
) -> AssertResult {
    let fin_ts = cap.frames()
        .direction(active_close_dir)
        .with_tcp_flags(TcpFlags::FIN)
        .map(|f| f.ts_ns)
        .last()
        .ok_or_else(|| TestFail::new(format!("{label}: no FIN found")))?;

    // Look for any non-ACK frame after the FIN from the same side
    // (e.g. a new SYN) that would indicate TIME_WAIT was exited.
    for f in cap.frames().direction(active_close_dir) {
        if f.ts_ns > fin_ts && !f.tcp.flags.has(TcpFlags::ACK) {
            let elapsed_ms = (f.ts_ns - fin_ts) / 1_000_000;
            if elapsed_ms < min_ms {
                return Err(TestFail::new(format!(
                    "{label}: TIME_WAIT exited after only {elapsed_ms}ms (< {min_ms}ms)"
                )));
            }
        }
    }
    Ok(())
}

// ── Socket-state assertions ───────────────────────────────────────────────────

/// Assert `sock.state` equals `want`.
pub fn assert_state(sock: &TcpSocket, want: State, label: &str) -> AssertResult {
    if sock.state != want {
        return Err(TestFail::new(format!(
            "{label}: expected state {want:?} but got {:?}", sock.state
        )));
    }
    Ok(())
}

/// Assert that `sock.last_error` equals `want`.
pub fn assert_error_fired(
    sock:  &TcpSocket,
    want:  TcpError,
    label: &str,
) -> AssertResult {
    match sock.last_error {
        Some(e) if e == want => Ok(()),
        other => Err(TestFail::new(format!(
            "{label}: expected error {want:?} but got {other:?}"
        ))),
    }
}

/// Assert that `result` is `Err(WouldBlock)`.
pub fn assert_would_block(r: rawket::Result<()>, label: &str) -> AssertResult {
    match r {
        Err(rawket::Error::WouldBlock) => Ok(()),
        other => Err(TestFail::new(format!(
            "{label}: expected WouldBlock but got {other:?}"
        ))),
    }
}

// ── Probe / keepalive assertions ──────────────────────────────────────────────

/// Assert `count` consecutive frames from `dir` each have no payload
/// (keepalive / persist probes).
pub fn assert_probe_sequence(
    cap:    &CaptureBuffer,
    dir:    Dir,
    count:  usize,
    label:  &str,
) -> AssertResult {
    let found = cap.frames()
        .direction(dir)
        .filter(|f| f.payload_len <= 1)
        .count();
    if found < count {
        return Err(TestFail::new(format!(
            "{label}: expected ≥{count} probes but found {found}"
        )));
    }
    Ok(())
}
