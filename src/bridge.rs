//! Software bridge for test network simulation.
//!
//! A [`Bridge`] sits between two [`Network<VirtualLink>`] uplinks and
//! forwards frames through a configurable impairment pipeline.
//!
//! # Quick start
//!
//! ```rust,ignore
//! use rawket::bridge::{Bridge, LinkProfile};
//!
//! let mut net_a = Network::new_virtual();
//! let mut net_b = Network::new_virtual();
//! let bridge = Network::bridge(net_a.uplink_mut(0), net_b.uplink_mut(0)).unwrap();
//! ```

use std::collections::BinaryHeap;
use std::cell::Cell;
use crate::virtual_link::VirtualLink;
use crate::af_packet::EtherLink;
use crate::filter::Filter;

// ── PRNG ──────────────────────────────────────────────────────────────────────

thread_local! {
    static PRNG: Cell<u64> = {
        let mut ts = libc::timespec { tv_sec: 0, tv_nsec: 0 };
        // SAFETY: clock_gettime is safe to call with a valid timespec pointer.
        unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) };
        let seed = (ts.tv_sec as u64)
            .wrapping_mul(1_000_000_000)
            .wrapping_add(ts.tv_nsec as u64);
        Cell::new(if seed == 0 { 1 } else { seed })
    };
}

fn next_u64() -> u64 {
    PRNG.with(|cell| {
        let mut x = cell.get();
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        cell.set(x);
        x
    })
}

/// Returns a value in [0.0, 1.0).
fn rand_f64() -> f64 {
    (next_u64() >> 11) as f64 / (1u64 << 53) as f64
}

// ── Loss ──────────────────────────────────────────────────────────────────────

/// Loss model for a directional link profile.
#[derive(Debug, Clone)]
pub enum Loss {
    /// No packet loss.
    None,
    /// Drop each packet independently with probability `rate` (0.0–1.0).
    Rate(f64),
    /// Two-state Markov loss model.
    ///
    /// `rate` = steady-state loss probability.
    /// `correlation` = probability of staying in the loss state (0.0–1.0).
    Correlated { rate: f64, correlation: f64 },
    /// Gilbert-Elliott 4-state model.
    ///
    /// `p` = P(Good→Bad), `r` = P(Bad→Good), `h` = P(loss | Bad),
    /// `k` = P(loss | Good).
    GilbertElliott { p: f64, r: f64, h: f64, k: f64 },
}

// ── Jitter ────────────────────────────────────────────────────────────────────

/// Jitter model for a directional link profile.
#[derive(Debug, Clone)]
pub enum Jitter {
    /// No additional jitter.
    None,
    /// Uniform jitter: adds between 0 and `2 * half_ms` milliseconds.
    Uniform(u64),
    /// Gaussian (Box-Muller) jitter.  Negative samples are clamped to 0.
    Normal { mean_ms: f64, std_dev_ms: f64 },
    /// Pareto type-II (heavy-tailed) jitter.
    Pareto { mean_ms: f64, std_dev_ms: f64 },
}

// ── Reorder ───────────────────────────────────────────────────────────────────

/// Reorder model for a directional link profile.
#[derive(Debug, Clone)]
pub struct Reorder {
    /// Probability that a given frame is held and reordered.
    pub rate: f64,
    /// How long (ms) to hold a frame before injecting it out-of-order.
    pub delay_ms: u64,
}

impl Reorder {
    /// No reordering.
    pub fn none() -> Self {
        Reorder { rate: 0.0, delay_ms: 0 }
    }

    /// Reorder `rate` fraction of frames with a default 50 ms hold time.
    pub fn rate(rate: f64) -> Self {
        Reorder { rate, delay_ms: 50 }
    }

    /// Override the hold delay (builder method).
    pub fn delay_ms(self, delay_ms: u64) -> Self {
        Reorder { delay_ms, ..self }
    }
}

// ── LossState ─────────────────────────────────────────────────────────────────

/// Per-direction persistent state for stateful loss models.
#[derive(Debug, Default)]
pub struct LossState {
    in_loss:    bool,
    ge_in_bad:  bool,
}

// ── DirectionProfile ──────────────────────────────────────────────────────────

/// One-way link characteristics.
#[derive(Debug, Clone)]
pub struct DirectionProfile {
    /// Base one-way latency in milliseconds.
    pub latency_ms:     u64,
    /// Serialization bandwidth in bits-per-second.  0 = unlimited.
    pub bandwidth_bps:  u64,
    /// Additional per-packet jitter model.
    pub jitter:         Jitter,
    /// Packet loss model.
    pub loss:           Loss,
    /// Reorder model.
    pub reorder:        Reorder,
    /// Probability that a frame is duplicated and sent twice.
    pub duplicate_rate: f64,
    /// Maximum frames held in the TX queue before drops.  0 = unlimited.
    pub queue_limit:    usize,
}

impl Default for DirectionProfile {
    fn default() -> Self {
        DirectionProfile {
            latency_ms:     0,
            bandwidth_bps:  0,
            jitter:         Jitter::None,
            loss:           Loss::None,
            reorder:        Reorder::none(),
            duplicate_rate: 0.0,
            queue_limit:    0,
        }
    }
}

impl DirectionProfile {
    /// Instantaneous, loss-free, unlimited-bandwidth profile.
    pub fn instant() -> Self {
        Self::default()
    }

    // ── Builder helpers ───────────────────────────────────────────────────────

    /// Set base latency.
    pub fn latency(self, ms: u64) -> Self {
        DirectionProfile { latency_ms: ms, ..self }
    }

    /// Set serialization bandwidth in bits per second.
    pub fn bandwidth_bps(self, bps: u64) -> Self {
        DirectionProfile { bandwidth_bps: bps, ..self }
    }

    /// Set bandwidth in kilobits per second.
    pub fn bandwidth_kbps(self, kbps: u64) -> Self {
        self.bandwidth_bps(kbps * 1_000)
    }

    /// Set bandwidth in megabits per second.
    pub fn bandwidth_mbps(self, mbps: u64) -> Self {
        self.bandwidth_bps(mbps * 1_000_000)
    }

    /// Set bandwidth in gigabits per second.
    pub fn bandwidth_gbps(self, gbps: u64) -> Self {
        self.bandwidth_bps(gbps * 1_000_000_000)
    }

    /// Set jitter model.
    pub fn jitter(self, j: Jitter) -> Self {
        DirectionProfile { jitter: j, ..self }
    }

    /// Set loss model.
    pub fn loss(self, l: Loss) -> Self {
        DirectionProfile { loss: l, ..self }
    }

    /// Set reorder model.
    pub fn reorder(self, r: Reorder) -> Self {
        DirectionProfile { reorder: r, ..self }
    }

    /// Set duplicate rate.
    pub fn duplicate_rate(self, rate: f64) -> Self {
        DirectionProfile { duplicate_rate: rate, ..self }
    }

    /// Set queue depth limit.
    pub fn queue(self, limit: usize) -> Self {
        DirectionProfile { queue_limit: limit, ..self }
    }

    // ── Internal helpers ──────────────────────────────────────────────────────

    /// Total one-way delay in milliseconds for a frame of `len` bytes.
    pub fn delay_ms(&self, len: usize) -> u64 {
        let serial_ms = if self.bandwidth_bps > 0 {
            (len as u64 * 8 * 1_000) / self.bandwidth_bps
        } else {
            0
        };
        let jitter_ms = self.sample_jitter();
        self.latency_ms + serial_ms + jitter_ms
    }

    fn sample_jitter(&self) -> u64 {
        match &self.jitter {
            Jitter::None => 0,
            Jitter::Uniform(half_ms) => {
                if *half_ms == 0 { return 0; }
                next_u64() % (half_ms * 2 + 1)
            }
            Jitter::Normal { mean_ms, std_dev_ms } => {
                let u1 = rand_f64().max(f64::MIN_POSITIVE);
                let u2 = rand_f64();
                let z = (-2.0 * u1.ln()).sqrt()
                    * (2.0 * core::f64::consts::PI * u2).cos();
                let v = mean_ms + std_dev_ms * z;
                if v < 0.0 { 0 } else { v as u64 }
            }
            Jitter::Pareto { mean_ms, std_dev_ms } => {
                let cv = std_dev_ms / mean_ms;
                let alpha = 1.0 / (cv * cv) + 2.0;
                let sigma = mean_ms * (alpha - 1.0);
                let u = rand_f64().max(f64::MIN_POSITIVE);
                let v = sigma * (u.powf(-1.0 / alpha) - 1.0);
                if v < 0.0 { 0 } else { v as u64 }
            }
        }
    }

    /// Returns `true` if the frame should be dropped.
    pub fn should_drop(&self, loss_state: &mut LossState) -> bool {
        match &self.loss {
            Loss::None => false,
            Loss::Rate(p) => rand_f64() < *p,
            Loss::Correlated { rate, correlation } => {
                let in_loss = loss_state.in_loss;
                let drop = if in_loss {
                    rand_f64() < *correlation || rand_f64() < *rate
                } else {
                    rand_f64() < *rate
                };
                loss_state.in_loss = drop;
                drop
            }
            Loss::GilbertElliott { p, r, h, k } => {
                loss_state.ge_in_bad = if loss_state.ge_in_bad {
                    rand_f64() >= *r
                } else {
                    rand_f64() < *p
                };
                if loss_state.ge_in_bad { rand_f64() < *h } else { rand_f64() < *k }
            }
        }
    }
}

// ── LinkProfile ───────────────────────────────────────────────────────────────

/// Bidirectional link characteristics.
pub struct LinkProfile {
    /// A→B direction.
    pub a_to_b: DirectionProfile,
    /// B→A direction.
    pub b_to_a: DirectionProfile,
}

impl LinkProfile {
    /// Same profile in both directions.
    pub fn symmetric(p: DirectionProfile) -> Self {
        LinkProfile { a_to_b: p.clone(), b_to_a: p }
    }

    /// Different profiles for each direction.
    pub fn asymmetric(a_to_b: DirectionProfile, b_to_a: DirectionProfile) -> Self {
        LinkProfile { a_to_b, b_to_a }
    }

    /// Transform the A→B direction.
    pub fn map_a_to_b(mut self, f: impl Fn(DirectionProfile) -> DirectionProfile) -> Self {
        self.a_to_b = f(self.a_to_b);
        self
    }

    /// Transform the B→A direction.
    pub fn map_b_to_a(mut self, f: impl Fn(DirectionProfile) -> DirectionProfile) -> Self {
        self.b_to_a = f(self.b_to_a);
        self
    }

    /// Transform both directions with the same function.
    pub fn map_both(mut self, f: impl Fn(DirectionProfile) -> DirectionProfile) -> Self {
        self.a_to_b = f(self.a_to_b);
        self.b_to_a = f(self.b_to_a);
        self
    }

    /// Instantaneous local loopback (zero latency, no loss, unlimited bandwidth).
    pub fn instant() -> Self {
        Self::symmetric(DirectionProfile::instant())
    }

    // ── Preset: LAN — Wired ───────────────────────────────────────────────────

    pub fn ethernet_10m() -> Self {
        Self::symmetric(DirectionProfile::instant().bandwidth_bps(10_000_000))
    }

    pub fn ethernet_100m() -> Self {
        Self::symmetric(DirectionProfile::instant().bandwidth_bps(100_000_000))
    }

    pub fn ethernet_1g() -> Self {
        Self::symmetric(DirectionProfile::instant().bandwidth_bps(1_000_000_000))
    }

    pub fn ethernet_10g() -> Self {
        Self::symmetric(DirectionProfile::instant().bandwidth_bps(10_000_000_000))
    }

    // ── Preset: LAN — WiFi ────────────────────────────────────────────────────

    pub fn wifi_b() -> Self {
        Self::symmetric(
            DirectionProfile::instant()
                .latency(10)
                .bandwidth_bps(5_500_000)
                .jitter(Jitter::Uniform(5))
                .loss(Loss::Rate(0.005)),
        )
    }

    pub fn wifi_g() -> Self {
        Self::symmetric(
            DirectionProfile::instant()
                .latency(7)
                .bandwidth_bps(22_000_000)
                .jitter(Jitter::Uniform(3))
                .loss(Loss::Rate(0.002)),
        )
    }

    pub fn wifi_n() -> Self {
        Self::symmetric(
            DirectionProfile::instant()
                .latency(4)
                .bandwidth_bps(150_000_000)
                .jitter(Jitter::Uniform(1))
                .loss(Loss::Rate(0.001)),
        )
    }

    pub fn wifi_ac() -> Self {
        Self::symmetric(
            DirectionProfile::instant()
                .latency(2)
                .bandwidth_bps(433_000_000)
                .jitter(Jitter::Uniform(1))
                .loss(Loss::Rate(0.0005)),
        )
    }

    pub fn wifi_ax() -> Self {
        Self::symmetric(
            DirectionProfile::instant()
                .latency(2)
                .bandwidth_bps(1_200_000_000)
                .jitter(Jitter::Uniform(0))
                .loss(Loss::Rate(0.0001)),
        )
    }

    // ── Preset: Broadband — Residential ──────────────────────────────────────

    pub fn dialup() -> Self {
        let dl = DirectionProfile::instant()
            .latency(150)
            .bandwidth_bps(56_000)
            .jitter(Jitter::Uniform(20))
            .loss(Loss::Rate(0.002));
        let ul = DirectionProfile::instant()
            .latency(150)
            .bandwidth_bps(33_600)
            .jitter(Jitter::Uniform(20))
            .loss(Loss::Rate(0.002));
        Self::asymmetric(dl, ul)
    }

    pub fn adsl() -> Self {
        let dl = DirectionProfile::instant()
            .latency(25)
            .bandwidth_bps(8_000_000)
            .jitter(Jitter::Uniform(10))
            .loss(Loss::Rate(0.002));
        let ul = DirectionProfile::instant()
            .latency(25)
            .bandwidth_bps(800_000)
            .jitter(Jitter::Uniform(10))
            .loss(Loss::Rate(0.002));
        Self::asymmetric(dl, ul)
    }

    pub fn vdsl2() -> Self {
        let dl = DirectionProfile::instant()
            .latency(9)
            .bandwidth_bps(100_000_000)
            .jitter(Jitter::Uniform(3))
            .loss(Loss::Rate(0.001));
        let ul = DirectionProfile::instant()
            .latency(9)
            .bandwidth_bps(40_000_000)
            .jitter(Jitter::Uniform(3))
            .loss(Loss::Rate(0.001));
        Self::asymmetric(dl, ul)
    }

    pub fn cable_docsis30() -> Self {
        let dl = DirectionProfile::instant()
            .latency(8)
            .bandwidth_bps(400_000_000)
            .jitter(Jitter::Uniform(5))
            .loss(Loss::Rate(0.002));
        let ul = DirectionProfile::instant()
            .latency(8)
            .bandwidth_bps(30_000_000)
            .jitter(Jitter::Uniform(5))
            .loss(Loss::Rate(0.002));
        Self::asymmetric(dl, ul)
    }

    pub fn cable_docsis31() -> Self {
        let dl = DirectionProfile::instant()
            .latency(5)
            .bandwidth_bps(1_000_000_000)
            .jitter(Jitter::Uniform(2))
            .loss(Loss::Rate(0.001));
        let ul = DirectionProfile::instant()
            .latency(5)
            .bandwidth_bps(200_000_000)
            .jitter(Jitter::Uniform(2))
            .loss(Loss::Rate(0.001));
        Self::asymmetric(dl, ul)
    }

    pub fn fiber_1g() -> Self {
        let dl = DirectionProfile::instant()
            .latency(3)
            .bandwidth_bps(1_000_000_000)
            .jitter(Jitter::Uniform(1))
            .loss(Loss::Rate(0.00005));
        let ul = DirectionProfile::instant()
            .latency(3)
            .bandwidth_bps(500_000_000)
            .jitter(Jitter::Uniform(1))
            .loss(Loss::Rate(0.00005));
        Self::asymmetric(dl, ul)
    }

    pub fn fiber_10g() -> Self {
        let dl = DirectionProfile::instant()
            .latency(2)
            .bandwidth_bps(10_000_000_000)
            .jitter(Jitter::Uniform(0))
            .loss(Loss::Rate(0.00005));
        let ul = DirectionProfile::instant()
            .latency(2)
            .bandwidth_bps(2_500_000_000)
            .jitter(Jitter::Uniform(0))
            .loss(Loss::Rate(0.00005));
        Self::asymmetric(dl, ul)
    }

    // ── Preset: Mobile ────────────────────────────────────────────────────────

    pub fn mobile_gprs() -> Self {
        Self::symmetric(
            DirectionProfile::instant()
                .latency(500)
                .bandwidth_bps(60_000)
                .jitter(Jitter::Uniform(100))
                .loss(Loss::Rate(0.01)),
        )
    }

    pub fn mobile_edge() -> Self {
        Self::symmetric(
            DirectionProfile::instant()
                .latency(250)
                .bandwidth_bps(200_000)
                .jitter(Jitter::Uniform(50))
                .loss(Loss::Rate(0.008)),
        )
    }

    pub fn mobile_3g() -> Self {
        Self::symmetric(
            DirectionProfile::instant()
                .latency(100)
                .bandwidth_bps(3_000_000)
                .jitter(Jitter::Uniform(20))
                .loss(Loss::Rate(0.003)),
        )
    }

    pub fn mobile_hspa() -> Self {
        Self::symmetric(
            DirectionProfile::instant()
                .latency(40)
                .bandwidth_bps(7_000_000)
                .jitter(Jitter::Uniform(10))
                .loss(Loss::Rate(0.002)),
        )
    }

    pub fn mobile_lte() -> Self {
        Self::symmetric(
            DirectionProfile::instant()
                .latency(20)
                .bandwidth_bps(50_000_000)
                .jitter(Jitter::Uniform(5))
                .loss(Loss::Rate(0.001)),
        )
    }

    pub fn mobile_lte_a() -> Self {
        Self::symmetric(
            DirectionProfile::instant()
                .latency(15)
                .bandwidth_bps(150_000_000)
                .jitter(Jitter::Uniform(3))
                .loss(Loss::Rate(0.0005)),
        )
    }

    pub fn mobile_5g() -> Self {
        Self::symmetric(
            DirectionProfile::instant()
                .latency(10)
                .bandwidth_bps(400_000_000)
                .jitter(Jitter::Uniform(2))
                .loss(Loss::Rate(0.0002)),
        )
    }

    pub fn mobile_5g_mmwave() -> Self {
        Self::symmetric(
            DirectionProfile::instant()
                .latency(3)
                .bandwidth_bps(2_000_000_000)
                .jitter(Jitter::Uniform(1))
                .loss(Loss::Rate(0.005)),
        )
    }

    // ── Preset: Satellite ─────────────────────────────────────────────────────

    pub fn satellite_geo() -> Self {
        Self::symmetric(
            DirectionProfile::instant()
                .latency(600)
                .bandwidth_bps(25_000_000)
                .jitter(Jitter::Uniform(100))
                .loss(Loss::Rate(0.01)),
        )
    }

    pub fn satellite_starlink() -> Self {
        Self::symmetric(
            DirectionProfile::instant()
                .latency(40)
                .bandwidth_bps(100_000_000)
                .jitter(Jitter::Uniform(15))
                .loss(Loss::Rate(0.002)),
        )
    }

    pub fn satellite_starlink_premium() -> Self {
        Self::symmetric(
            DirectionProfile::instant()
                .latency(25)
                .bandwidth_bps(250_000_000)
                .jitter(Jitter::Uniform(8))
                .loss(Loss::Rate(0.001)),
        )
    }

    pub fn satellite_oneweb() -> Self {
        Self::symmetric(
            DirectionProfile::instant()
                .latency(50)
                .bandwidth_bps(200_000_000)
                .jitter(Jitter::Uniform(20))
                .loss(Loss::Rate(0.002)),
        )
    }

    // ── Preset: Leased Lines / WAN ────────────────────────────────────────────

    pub fn t1() -> Self {
        Self::symmetric(
            DirectionProfile::instant()
                .latency(5)
                .bandwidth_bps(1_544_000)
                .jitter(Jitter::Uniform(1))
                .loss(Loss::Rate(0.0005)),
        )
    }

    pub fn e1() -> Self {
        Self::symmetric(
            DirectionProfile::instant()
                .latency(4)
                .bandwidth_bps(2_048_000)
                .jitter(Jitter::Uniform(1))
                .loss(Loss::Rate(0.0005)),
        )
    }

    pub fn t3() -> Self {
        Self::symmetric(
            DirectionProfile::instant()
                .latency(3)
                .bandwidth_bps(44_736_000)
                .jitter(Jitter::Uniform(0))
                .loss(Loss::Rate(0.0001)),
        )
    }

    pub fn wan_mpls() -> Self {
        Self::symmetric(
            DirectionProfile::instant()
                .latency(10)
                .bandwidth_bps(100_000_000)
                .jitter(Jitter::Uniform(1))
                .loss(Loss::Rate(0.00001)),
        )
    }

    // ── Preset: Long-haul fiber ───────────────────────────────────────────────

    pub fn fiber_us_continental() -> Self {
        Self::symmetric(
            DirectionProfile::instant()
                .latency(30)
                .bandwidth_bps(100_000_000_000)
                .jitter(Jitter::Uniform(1))
                .loss(Loss::Rate(0.000001)),
        )
    }

    pub fn fiber_transatlantic() -> Self {
        Self::symmetric(
            DirectionProfile::instant()
                .latency(65)
                .bandwidth_bps(100_000_000_000)
                .jitter(Jitter::Uniform(2))
                .loss(Loss::Rate(0.000001)),
        )
    }
}

// ── DelayQueue ────────────────────────────────────────────────────────────────

struct DelayedFrame {
    deliver_at_ms: u64,
    data:          std::vec::Vec<u8>,
}

impl PartialEq for DelayedFrame {
    fn eq(&self, other: &Self) -> bool {
        self.deliver_at_ms == other.deliver_at_ms
    }
}

impl Eq for DelayedFrame {}

impl PartialOrd for DelayedFrame {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for DelayedFrame {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        // Reverse so BinaryHeap (max-heap) acts as a min-heap.
        other.deliver_at_ms.cmp(&self.deliver_at_ms)
    }
}

struct DelayQueue {
    heap: BinaryHeap<DelayedFrame>,
}

impl DelayQueue {
    fn new() -> Self {
        DelayQueue { heap: BinaryHeap::new() }
    }

    fn push(&mut self, deliver_at_ms: u64, data: std::vec::Vec<u8>) {
        self.heap.push(DelayedFrame { deliver_at_ms, data });
    }

    fn pop_ready(&mut self, now_ms: u64) -> Option<std::vec::Vec<u8>> {
        if self.heap.peek().is_some_and(|f| f.deliver_at_ms <= now_ms) {
            self.heap.pop().map(|f| f.data)
        } else {
            None
        }
    }

    fn next_deadline(&self) -> Option<u64> {
        self.heap.peek().map(|f| f.deliver_at_ms)
    }

    fn is_empty(&self) -> bool {
        self.heap.is_empty()
    }
}

// ── PacketSpec ────────────────────────────────────────────────────────────────

/// Specifies which packets an impairment or capture rule applies to.
pub struct PacketSpec {
    predicate: Option<Filter>,
    /// Match only the nth occurrence (1-based).  `None` = every match.
    nth:       Option<usize>,
    count:     usize,
}

impl PacketSpec {
    /// Match every packet.
    pub fn any() -> Self {
        PacketSpec { predicate: None, nth: None, count: 0 }
    }

    /// Match only the nth packet.
    pub fn nth(n: usize) -> Self {
        PacketSpec { predicate: None, nth: Some(n), count: 0 }
    }

    /// Match every packet satisfying `f`.
    pub fn matching(f: Filter) -> Self {
        PacketSpec { predicate: Some(f), nth: None, count: 0 }
    }

    /// Match only the nth packet satisfying `f`.
    pub fn nth_matching(n: usize, f: Filter) -> Self {
        PacketSpec { predicate: Some(f), nth: Some(n), count: 0 }
    }

    /// Returns `true` and increments the internal counter if this spec matches.
    fn matches(&mut self, frame: &[u8]) -> bool {
        let predicate_ok = self.predicate.as_ref().is_none_or(|f| f.matches(frame));
        if !predicate_ok {
            return false;
        }
        self.count += 1;
        match self.nth {
            None    => true,
            Some(n) => self.count == n,
        }
    }
}

// ── Impairment ────────────────────────────────────────────────────────────────

/// A mutation applied to forwarded frames.
pub enum Impairment {
    /// Drop frames matching the spec.
    Drop(PacketSpec),
    /// Corrupt a specific byte in frames matching the spec.
    Corrupt {
        when:     PacketSpec,
        byte_idx: usize,
        xor_mask: u8,
    },
}

impl Impairment {
    fn apply(&mut self, frame: &[u8]) -> Option<std::vec::Vec<u8>> {
        match self {
            Impairment::Drop(spec) => {
                if spec.matches(frame) { None } else { Some(frame.to_vec()) }
            }
            Impairment::Corrupt { when, byte_idx, xor_mask } => {
                if when.matches(frame) {
                    let mut data = frame.to_vec();
                    if *byte_idx < data.len() {
                        data[*byte_idx] ^= *xor_mask;
                    }
                    Some(data)
                } else {
                    Some(frame.to_vec())
                }
            }
        }
    }
}

// ── CaptureBuffer ─────────────────────────────────────────────────────────────

/// Frame capture buffer with per-direction history.
#[derive(Default)]
pub struct CaptureBuffer {
    /// Frames forwarded from A to B (captured before impairments).
    pub a_to_b: std::vec::Vec<std::vec::Vec<u8>>,
    /// Frames forwarded from B to A (captured before impairments).
    pub b_to_a: std::vec::Vec<std::vec::Vec<u8>>,
}

impl CaptureBuffer {
    pub fn new() -> Self {
        CaptureBuffer::default()
    }

    pub fn clear(&mut self) {
        self.a_to_b.clear();
        self.b_to_a.clear();
    }
}

// ── Direction ─────────────────────────────────────────────────────────────────

enum Direction {
    AToB,
    BToA,
}

// ── Bridge ────────────────────────────────────────────────────────────────────

/// Software bridge between two virtual uplinks.
///
/// Receives frames from each side, applies optional impairments and link
/// profile, and delivers them to the peer side.
pub struct Bridge {
    /// Receives from net_a; TX goes into net_a.
    link_a:                VirtualLink,
    /// Receives from net_b; TX goes into net_b.
    link_b:                VirtualLink,
    pub capture:           CaptureBuffer,
    profile:               LinkProfile,
    impairments_a_to_b:    std::vec::Vec<Impairment>,
    impairments_b_to_a:    std::vec::Vec<Impairment>,
    loss_state_a_to_b:     LossState,
    loss_state_b_to_a:     LossState,
    delay_a_to_b:          DelayQueue,
    delay_b_to_a:          DelayQueue,
}

impl Bridge {
    /// Create a bridge with an instant (zero-latency) profile.
    pub fn new() -> Self {
        Bridge {
            link_a:             VirtualLink::new(),
            link_b:             VirtualLink::new(),
            capture:            CaptureBuffer::new(),
            profile:            LinkProfile::instant(),
            impairments_a_to_b: std::vec::Vec::new(),
            impairments_b_to_a: std::vec::Vec::new(),
            loss_state_a_to_b:  LossState::default(),
            loss_state_b_to_a:  LossState::default(),
            delay_a_to_b:       DelayQueue::new(),
            delay_b_to_a:       DelayQueue::new(),
        }
    }

    /// Set the link profile (builder method).
    pub fn with_profile(mut self, profile: LinkProfile) -> Self {
        self.profile = profile;
        self
    }

    /// Replace the link profile at runtime.
    pub fn set_profile(&mut self, profile: LinkProfile) {
        self.profile = profile;
    }

    /// Add an impairment on the A→B path.
    pub fn add_impairment_a_to_b(&mut self, imp: Impairment) {
        self.impairments_a_to_b.push(imp);
    }

    /// Add an impairment on the B→A path.
    pub fn add_impairment_b_to_a(&mut self, imp: Impairment) {
        self.impairments_b_to_a.push(imp);
    }

    /// Mutable reference to the A-side link (for wiring to an uplink).
    pub(crate) fn link_a_mut(&mut self) -> &mut VirtualLink {
        &mut self.link_a
    }

    /// Mutable reference to the B-side link (for wiring to an uplink).
    pub(crate) fn link_b_mut(&mut self) -> &mut VirtualLink {
        &mut self.link_b
    }

    /// Drain frames from the A side, apply impairments + profile, deliver to B.
    ///
    /// Returns the number of frames read from A.
    pub fn deliver_a_to_b(&mut self) -> usize {
        self.do_deliver(Direction::AToB)
    }

    /// Drain frames from the B side, apply impairments + profile, deliver to A.
    ///
    /// Returns the number of frames read from B.
    pub fn deliver_b_to_a(&mut self) -> usize {
        self.do_deliver(Direction::BToA)
    }

    /// Advance time: deliver any frames whose deadline has passed.
    pub fn tick(&mut self) {
        let now = crate::timers::now_ms();
        self.flush_delay_queue(Direction::AToB, now);
        self.flush_delay_queue(Direction::BToA, now);
    }

    /// Force-deliver all pending delayed frames regardless of their deadline.
    pub fn flush(&mut self) {
        self.flush_delay_queue(Direction::AToB, u64::MAX);
        self.flush_delay_queue(Direction::BToA, u64::MAX);
    }

    /// Return the earliest pending delivery deadline across both queues.
    pub fn next_deadline_ms(&self) -> Option<u64> {
        match (self.delay_a_to_b.next_deadline(), self.delay_b_to_a.next_deadline()) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (Some(a), None)    => Some(a),
            (None,    Some(b)) => Some(b),
            (None,    None)    => None,
        }
    }

    /// Returns `true` if both delay queues are empty.
    pub fn is_idle(&self) -> bool {
        self.delay_a_to_b.is_empty() && self.delay_b_to_a.is_empty()
    }

    // ── Internal delivery implementation ──────────────────────────────────────

    fn do_deliver(&mut self, dir: Direction) -> usize {
        let mut count = 0;

        loop {
            // Receive a frame from the source side.
            let frame = match dir {
                Direction::AToB => {
                    let Some(f) = self.link_a.rx_recv() else { break };
                    let data = f.to_vec();
                    self.link_a.rx_release();
                    data
                }
                Direction::BToA => {
                    let Some(f) = self.link_b.rx_recv() else { break };
                    let data = f.to_vec();
                    self.link_b.rx_release();
                    data
                }
            };
            count += 1;

            // Capture (before impairments).
            match dir {
                Direction::AToB => self.capture.a_to_b.push(frame.clone()),
                Direction::BToA => self.capture.b_to_a.push(frame.clone()),
            }

            // Apply impairments.
            let imps = match dir {
                Direction::AToB => &mut self.impairments_a_to_b,
                Direction::BToA => &mut self.impairments_b_to_a,
            };
            let mut data: Option<std::vec::Vec<u8>> = Some(frame);
            for imp in imps.iter_mut() {
                data = data.and_then(|f| imp.apply(&f));
                if data.is_none() {
                    break;
                }
            }
            let data = match data {
                Some(d) => d,
                None    => continue,
            };

            // Apply profile: loss + delay.
            let (drop_it, delay_ms_val, dup_rate) = {
                let (profile, loss_state) = match dir {
                    Direction::AToB => (&self.profile.a_to_b, &mut self.loss_state_a_to_b),
                    Direction::BToA => (&self.profile.b_to_a, &mut self.loss_state_b_to_a),
                };
                let drop = profile.should_drop(loss_state);
                let delay = profile.delay_ms(data.len());
                let dup   = profile.duplicate_rate;
                (drop, delay, dup)
            };

            if drop_it {
                continue;
            }

            self.forward_frame(&dir, data.clone(), delay_ms_val, dup_rate);
        }

        count
    }

    fn forward_frame(
        &mut self,
        dir:         &Direction,
        data:        std::vec::Vec<u8>,
        delay_ms:    u64,
        dup_rate:    f64,
    ) {
        if delay_ms == 0 {
            // Immediate delivery.
            let _ = match dir {
                Direction::AToB => self.link_b.tx_send(&data),
                Direction::BToA => self.link_a.tx_send(&data),
            };
            if rand_f64() < dup_rate {
                let _ = match dir {
                    Direction::AToB => self.link_b.tx_send(&data),
                    Direction::BToA => self.link_a.tx_send(&data),
                };
            }
        } else {
            let now       = crate::timers::now_ms();
            let deliver_at = now + delay_ms;
            let dq = match dir {
                Direction::AToB => &mut self.delay_a_to_b,
                Direction::BToA => &mut self.delay_b_to_a,
            };
            dq.push(deliver_at, data);
        }
    }

    fn flush_delay_queue(&mut self, dir: Direction, now: u64) {
        loop {
            let dq = match dir {
                Direction::AToB => &mut self.delay_a_to_b,
                Direction::BToA => &mut self.delay_b_to_a,
            };
            let Some(frame) = dq.pop_ready(now) else { break };
            let _ = match dir {
                Direction::AToB => self.link_b.tx_send(&frame),
                Direction::BToA => self.link_a.tx_send(&frame),
            };
        }
    }
}

impl Default for Bridge {
    fn default() -> Self {
        Self::new()
    }
}

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_arp_frame() -> std::vec::Vec<u8> {
        let mut f = std::vec![0u8; 42];
        f[0..6].copy_from_slice(&[0xff; 6]);
        f[6..12].copy_from_slice(&[0x11, 0x22, 0x33, 0x44, 0x55, 0x66]);
        f[12..14].copy_from_slice(&[0x08, 0x06]);
        f
    }

    #[test]
    fn instant_delivery() {
        let mut bridge = Bridge::new();

        // Wire uplinks to the bridge links
        crate::virtual_link::connect(
            bridge.link_a_mut(),
            &mut VirtualLink::new(),
        );
        // Use direct tx_send on bridge's link_a; bridge link_b just needs a peer too.
        // Simpler: wire them together with another standalone VirtualLink pair.

        // Actually let's just wire bridge.link_a → some external VirtualLink,
        // and bridge.link_b → another.
        let mut peer_a = VirtualLink::new();
        let mut peer_b = VirtualLink::new();

        // Re-create bridge to get fresh links for the test.
        let mut bridge = Bridge::new();
        crate::virtual_link::connect(&mut peer_a, bridge.link_a_mut());
        crate::virtual_link::connect(&mut peer_b, bridge.link_b_mut());

        // peer_a sends a frame → should appear on peer_b after deliver_a_to_b
        peer_a.tx_send(&make_arp_frame()).unwrap();
        let n = bridge.deliver_a_to_b();
        assert_eq!(n, 1);

        let received = peer_b.rx_recv();
        assert!(received.is_some());
    }

    #[test]
    fn drop_impairment() {
        let mut bridge = Bridge::new();
        let mut peer_a = VirtualLink::new();
        let mut peer_b = VirtualLink::new();
        crate::virtual_link::connect(&mut peer_a, bridge.link_a_mut());
        crate::virtual_link::connect(&mut peer_b, bridge.link_b_mut());

        // Drop the first frame A→B
        bridge.add_impairment_a_to_b(Impairment::Drop(PacketSpec::nth(1)));

        peer_a.tx_send(&make_arp_frame()).unwrap();
        peer_a.tx_send(&make_arp_frame()).unwrap();
        bridge.deliver_a_to_b();

        // First frame dropped, second delivered
        let f1 = peer_b.rx_recv();
        assert!(f1.is_some()); // second frame
        peer_b.rx_release();
        let f2 = peer_b.rx_recv();
        assert!(f2.is_none()); // no third frame
    }

    #[test]
    fn capture_records_frames() {
        let mut bridge = Bridge::new();
        let mut peer_a = VirtualLink::new();
        let mut peer_b = VirtualLink::new();
        crate::virtual_link::connect(&mut peer_a, bridge.link_a_mut());
        crate::virtual_link::connect(&mut peer_b, bridge.link_b_mut());

        peer_a.tx_send(&make_arp_frame()).unwrap();
        bridge.deliver_a_to_b();

        assert_eq!(bridge.capture.a_to_b.len(), 1);
        assert!(bridge.capture.b_to_a.is_empty());
    }

    #[test]
    fn link_profile_instant_fields() {
        let p = LinkProfile::instant();
        assert_eq!(p.a_to_b.latency_ms, 0);
        assert_eq!(p.a_to_b.bandwidth_bps, 0);
        assert_eq!(p.b_to_a.latency_ms, 0);
    }

    #[test]
    fn link_profile_presets_compile() {
        // Just verify all preset constructors don't panic.
        let _ = LinkProfile::ethernet_10m();
        let _ = LinkProfile::ethernet_100m();
        let _ = LinkProfile::ethernet_1g();
        let _ = LinkProfile::ethernet_10g();
        let _ = LinkProfile::wifi_b();
        let _ = LinkProfile::wifi_g();
        let _ = LinkProfile::wifi_n();
        let _ = LinkProfile::wifi_ac();
        let _ = LinkProfile::wifi_ax();
        let _ = LinkProfile::dialup();
        let _ = LinkProfile::adsl();
        let _ = LinkProfile::vdsl2();
        let _ = LinkProfile::cable_docsis30();
        let _ = LinkProfile::cable_docsis31();
        let _ = LinkProfile::fiber_1g();
        let _ = LinkProfile::fiber_10g();
        let _ = LinkProfile::mobile_gprs();
        let _ = LinkProfile::mobile_edge();
        let _ = LinkProfile::mobile_3g();
        let _ = LinkProfile::mobile_hspa();
        let _ = LinkProfile::mobile_lte();
        let _ = LinkProfile::mobile_lte_a();
        let _ = LinkProfile::mobile_5g();
        let _ = LinkProfile::mobile_5g_mmwave();
        let _ = LinkProfile::satellite_geo();
        let _ = LinkProfile::satellite_starlink();
        let _ = LinkProfile::satellite_starlink_premium();
        let _ = LinkProfile::satellite_oneweb();
        let _ = LinkProfile::t1();
        let _ = LinkProfile::e1();
        let _ = LinkProfile::t3();
        let _ = LinkProfile::wan_mpls();
        let _ = LinkProfile::fiber_us_continental();
        let _ = LinkProfile::fiber_transatlantic();
    }

    #[test]
    fn loss_rate_zero_never_drops() {
        let profile = DirectionProfile::instant().loss(Loss::Rate(0.0));
        let mut state = LossState::default();
        for _ in 0..1000 {
            assert!(!profile.should_drop(&mut state));
        }
    }

    #[test]
    fn loss_rate_one_always_drops() {
        let profile = DirectionProfile::instant().loss(Loss::Rate(1.0));
        let mut state = LossState::default();
        for _ in 0..100 {
            assert!(profile.should_drop(&mut state));
        }
    }

    #[test]
    fn delay_queue_min_heap() {
        let mut dq = DelayQueue::new();
        dq.push(100, vec![1]);
        dq.push(50,  vec![2]);
        dq.push(200, vec![3]);
        // Should pop in ascending order of deliver_at_ms
        assert_eq!(dq.pop_ready(200).unwrap(), vec![2]);
        assert_eq!(dq.pop_ready(200).unwrap(), vec![1]);
        assert_eq!(dq.pop_ready(200).unwrap(), vec![3]);
        assert!(dq.pop_ready(200).is_none());
    }

    #[test]
    fn corrupt_impairment_flips_byte() {
        let mut bridge = Bridge::new();
        let mut peer_a = VirtualLink::new();
        let mut peer_b = VirtualLink::new();
        crate::virtual_link::connect(&mut peer_a, bridge.link_a_mut());
        crate::virtual_link::connect(&mut peer_b, bridge.link_b_mut());

        bridge.add_impairment_a_to_b(Impairment::Corrupt {
            when:     PacketSpec::any(),
            byte_idx: 0,
            xor_mask: 0xff,
        });

        let frame = make_arp_frame();
        peer_a.tx_send(&frame).unwrap();
        bridge.deliver_a_to_b();

        let received = peer_b.rx_recv().unwrap();
        // First byte of dst MAC (0xff) XORed with 0xff → 0x00
        assert_eq!(received[0], 0x00);
    }

    #[test]
    fn deliver_b_to_a_direction() {
        let mut bridge = Bridge::new();
        let mut peer_a = VirtualLink::new();
        let mut peer_b = VirtualLink::new();
        crate::virtual_link::connect(&mut peer_a, bridge.link_a_mut());
        crate::virtual_link::connect(&mut peer_b, bridge.link_b_mut());

        // B sends a frame; it should arrive at A after deliver_b_to_a.
        peer_b.tx_send(&make_arp_frame()).unwrap();
        let n = bridge.deliver_b_to_a();
        assert_eq!(n, 1);
        assert!(peer_a.rx_recv().is_some());
        assert!(bridge.capture.b_to_a.len() == 1);
        assert!(bridge.capture.a_to_b.is_empty());
    }

    #[test]
    fn packet_spec_nth_second_frame() {
        // nth(2) should pass only the 2nd frame, drop the rest.
        let mut bridge = Bridge::new();
        let mut peer_a = VirtualLink::new();
        let mut peer_b = VirtualLink::new();
        crate::virtual_link::connect(&mut peer_a, bridge.link_a_mut());
        crate::virtual_link::connect(&mut peer_b, bridge.link_b_mut());

        bridge.add_impairment_a_to_b(Impairment::Drop(PacketSpec::nth(2)));

        // Send 3 frames.
        peer_a.tx_send(&[0x01; 42]).unwrap();
        peer_a.tx_send(&[0x02; 42]).unwrap();
        peer_a.tx_send(&[0x03; 42]).unwrap();
        bridge.deliver_a_to_b();

        // Frame 2 was dropped; frames 1 and 3 delivered.
        let f1 = peer_b.rx_recv().unwrap().to_vec(); peer_b.rx_release();
        let f2 = peer_b.rx_recv().unwrap().to_vec(); peer_b.rx_release();
        assert!(peer_b.rx_recv().is_none());
        assert_eq!(f1[0], 0x01);
        assert_eq!(f2[0], 0x03);
    }

    #[test]
    fn packet_spec_matching_filter_drops_only_matching() {
        let mut bridge = Bridge::new();
        let mut peer_a = VirtualLink::new();
        let mut peer_b = VirtualLink::new();
        crate::virtual_link::connect(&mut peer_a, bridge.link_a_mut());
        crate::virtual_link::connect(&mut peer_b, bridge.link_b_mut());

        // Drop only frames whose first byte is 0xaa (Broadcast check via ByteAt).
        let spec = PacketSpec::matching(
            crate::filter::Filter::ByteAt {
                offset: 0,
                op:     crate::filter::CmpOp::Eq,
                value:  0xaa,
            },
        );
        bridge.add_impairment_a_to_b(Impairment::Drop(spec));

        peer_a.tx_send(&[0xaa; 42]).unwrap(); // matches → dropped
        peer_a.tx_send(&[0xbb; 42]).unwrap(); // no match → forwarded
        bridge.deliver_a_to_b();

        let received = peer_b.rx_recv().unwrap().to_vec();
        peer_b.rx_release();
        assert!(peer_b.rx_recv().is_none());
        assert_eq!(received[0], 0xbb);
    }

    #[test]
    fn impairment_on_b_to_a_direction() {
        let mut bridge = Bridge::new();
        let mut peer_a = VirtualLink::new();
        let mut peer_b = VirtualLink::new();
        crate::virtual_link::connect(&mut peer_a, bridge.link_a_mut());
        crate::virtual_link::connect(&mut peer_b, bridge.link_b_mut());

        // Corrupt first byte on the B→A path.
        bridge.add_impairment_b_to_a(Impairment::Corrupt {
            when:     PacketSpec::any(),
            byte_idx: 0,
            xor_mask: 0xff,
        });

        let frame = [0x12u8; 42];
        peer_b.tx_send(&frame).unwrap();
        bridge.deliver_b_to_a();

        let received = peer_a.rx_recv().unwrap();
        assert_eq!(received[0], 0x12 ^ 0xff);
        peer_a.rx_release();
    }

    #[test]
    fn corrupt_out_of_bounds_byte_idx_safe() {
        // byte_idx beyond frame length should not corrupt anything.
        let mut bridge = Bridge::new();
        let mut peer_a = VirtualLink::new();
        let mut peer_b = VirtualLink::new();
        crate::virtual_link::connect(&mut peer_a, bridge.link_a_mut());
        crate::virtual_link::connect(&mut peer_b, bridge.link_b_mut());

        bridge.add_impairment_a_to_b(Impairment::Corrupt {
            when:     PacketSpec::any(),
            byte_idx: 9999,
            xor_mask: 0xff,
        });

        let frame = make_arp_frame();
        peer_a.tx_send(&frame).unwrap();
        bridge.deliver_a_to_b();

        // Frame should be received unmodified.
        let received = peer_b.rx_recv().unwrap().to_vec();
        assert_eq!(received, frame);
    }

    #[test]
    fn capture_dropped_frames_still_captured() {
        // Capture happens before impairments, so dropped frames still appear in the buffer.
        let mut bridge = Bridge::new();
        let mut peer_a = VirtualLink::new();
        let mut peer_b = VirtualLink::new();
        crate::virtual_link::connect(&mut peer_a, bridge.link_a_mut());
        crate::virtual_link::connect(&mut peer_b, bridge.link_b_mut());

        bridge.add_impairment_a_to_b(Impairment::Drop(PacketSpec::any()));

        peer_a.tx_send(&make_arp_frame()).unwrap();
        bridge.deliver_a_to_b();

        // Nothing forwarded to B.
        assert!(peer_b.rx_recv().is_none());
        // But frame was captured before it was dropped.
        assert_eq!(bridge.capture.a_to_b.len(), 1);
    }

    #[test]
    fn capture_clear() {
        let mut bridge = Bridge::new();
        let mut peer_a = VirtualLink::new();
        let mut peer_b = VirtualLink::new();
        crate::virtual_link::connect(&mut peer_a, bridge.link_a_mut());
        crate::virtual_link::connect(&mut peer_b, bridge.link_b_mut());

        peer_a.tx_send(&make_arp_frame()).unwrap();
        bridge.deliver_a_to_b();
        assert_eq!(bridge.capture.a_to_b.len(), 1);

        bridge.capture.clear();
        assert!(bridge.capture.a_to_b.is_empty());
        assert!(bridge.capture.b_to_a.is_empty());
    }

    #[test]
    fn flush_delivers_latency_delayed_frames() {
        // A profile with 1000 ms latency means frames sit in the delay queue
        // until tick()/flush() releases them.
        let mut bridge = Bridge::new();
        let mut peer_a = VirtualLink::new();
        let mut peer_b = VirtualLink::new();
        crate::virtual_link::connect(&mut peer_a, bridge.link_a_mut());
        crate::virtual_link::connect(&mut peer_b, bridge.link_b_mut());

        bridge.set_profile(LinkProfile::symmetric(
            DirectionProfile::instant().latency(1_000),
        ));

        peer_a.tx_send(&make_arp_frame()).unwrap();
        bridge.deliver_a_to_b();

        // Not yet delivered (delay queue holds it).
        assert!(peer_b.rx_recv().is_none());
        assert!(!bridge.is_idle());
        assert!(bridge.next_deadline_ms().is_some());

        // flush() forces delivery regardless of wall clock.
        bridge.flush();
        assert!(bridge.is_idle());
        assert!(peer_b.rx_recv().is_some());
    }

    #[test]
    fn delay_ms_serialization_calculation() {
        // 8000 bps → 1 byte/ms. A 100-byte frame costs 100 ms of serialization
        // plus whatever base latency is set.
        let profile = DirectionProfile::instant()
            .latency(10)
            .bandwidth_bps(8_000)
            .jitter(Jitter::None);
        // delay = 10 + (100 * 8 * 1000) / 8000 = 10 + 100 = 110
        assert_eq!(profile.delay_ms(100), 110);
        // Zero bandwidth means no serialization delay.
        let no_bw = DirectionProfile::instant().latency(5);
        assert_eq!(no_bw.delay_ms(1000), 5);
    }

    #[test]
    fn asymmetric_preset_has_different_directions() {
        let adsl = LinkProfile::adsl();
        // DL (a_to_b) is 8 Mbps, UL (b_to_a) is 800 kbps.
        assert!(adsl.a_to_b.bandwidth_bps > adsl.b_to_a.bandwidth_bps);
        assert_eq!(adsl.a_to_b.bandwidth_bps, 8_000_000);
        assert_eq!(adsl.b_to_a.bandwidth_bps, 800_000);
    }

    #[test]
    fn map_both_modifies_both_directions() {
        let profile = LinkProfile::instant()
            .map_both(|d| d.latency(42));
        assert_eq!(profile.a_to_b.latency_ms, 42);
        assert_eq!(profile.b_to_a.latency_ms, 42);
    }

    #[test]
    fn map_a_to_b_leaves_b_to_a_unchanged() {
        let profile = LinkProfile::asymmetric(
            DirectionProfile::instant().latency(10),
            DirectionProfile::instant().latency(20),
        ).map_a_to_b(|d| d.latency(99));
        assert_eq!(profile.a_to_b.latency_ms, 99);
        assert_eq!(profile.b_to_a.latency_ms, 20);
    }

    #[test]
    fn loss_correlated_rate_one_always_drops() {
        // With rate=1.0 and high correlation, every frame should be dropped.
        let profile = DirectionProfile::instant()
            .loss(Loss::Correlated { rate: 1.0, correlation: 1.0 });
        let mut state = LossState::default();
        for _ in 0..100 {
            assert!(profile.should_drop(&mut state));
        }
    }
}
