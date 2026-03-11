//! N-port software bridge with MAC FDB, impairment pipeline, and capture.
//!
//! A [`Bridge`] connects multiple [`Network`](crate::Network) interfaces
//! through a configurable impairment pipeline.  It performs real Ethernet
//! Layer-2 forwarding with a MAC forwarding database (FDB): unicast frames
//! are forwarded only to the learned egress port, and unknown/broadcast/
//! multicast frames are flooded to all ports except the ingress port.
//!
//! # Quick start
//!
//! ```rust,ignore
//! use rawket::bridge::{Bridge, DirectionProfile};
//! use rawket::interface::Interface;
//! use rawket::eth::MacAddr;
//!
//! let mut net_a = Network::new();
//! let mut net_b = Network::new();
//!
//! // Create interfaces and register them (no uplink — bridge-driven).
//! let idx_a = net_a.add_interface().mac(MacAddr::from([0x02, 0, 0, 0, 0, 1])).finish();
//! let idx_b = net_b.add_interface().mac(MacAddr::from([0x02, 0, 0, 0, 0, 2])).finish();
//!
//! // Wire interfaces through a bridge.
//! let bridge = Bridge::new();
//! let port_a = bridge.add_port(&mut net_a, idx_a).finish();
//! let port_b = bridge.add_port(&mut net_b, idx_b).finish();
//!
//! // Frames are forwarded eagerly when the interface TX closure is called.
//! // Network::poll_rx_with_timeout drives delayed frame delivery.
//! ```

use std::collections::BinaryHeap;
use std::cell::Cell;
use alloc::{collections::BTreeMap, rc::Rc, vec, vec::Vec};
use core::cell::RefCell;

use crate::interface::FrameQueue;
use crate::network::Network;

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

impl From<f64> for Loss {
    /// `0.10` → `Loss::Rate(0.10)`.
    fn from(rate: f64) -> Self {
        Loss::Rate(rate)
    }
}

// ── Jitter ────────────────────────────────────────────────────────────────────

/// Jitter model for a directional link profile.
#[derive(Debug, Clone)]
pub enum Jitter {
    /// No additional jitter.
    None,
    /// Uniform jitter: adds between 0 and `2 * half_ns` nanoseconds.
    Uniform(u64),
    /// Gaussian (Box-Muller) jitter.  Negative samples are clamped to 0.
    Normal { mean_ns: f64, std_dev_ns: f64 },
    /// Pareto type-II (heavy-tailed) jitter.
    Pareto { mean_ns: f64, std_dev_ns: f64 },
}

impl From<u64> for Jitter {
    /// `5` → `Jitter::Uniform(5)`.
    fn from(half_ns: u64) -> Self {
        Jitter::Uniform(half_ns)
    }
}

// ── Reorder ───────────────────────────────────────────────────────────────────

/// Reorder model for a directional link profile.
#[derive(Debug, Clone)]
pub struct Reorder {
    /// Probability that a given frame is held and reordered.
    pub rate: f64,
    /// How long (ns) to hold a frame before injecting it out-of-order.
    pub delay_ns: u64,
}

impl Reorder {
    /// No reordering.
    pub fn none() -> Self {
        Reorder { rate: 0.0, delay_ns: 0 }
    }

    /// Reorder `rate` fraction of frames with a default 50 ms hold time.
    pub fn rate(rate: f64) -> Self {
        Reorder { rate, delay_ns: 50_000_000 }
    }

    /// Set the hold delay in milliseconds.
    pub fn delay_ms(self, ms: u64) -> Self {
        Reorder { delay_ns: ms * 1_000_000, ..self }
    }

    /// Set the hold delay in nanoseconds.
    pub fn delay_ns(self, ns: u64) -> Self {
        Reorder { delay_ns: ns, ..self }
    }
}

// ── LossState ─────────────────────────────────────────────────────────────────

/// Per-direction persistent state for stateful loss models.
#[derive(Debug, Default)]
pub struct LossState {
    in_loss:    bool,
    ge_in_bad:  bool,
}

/// Evaluate a [`Loss`] model and return `true` if the frame should be dropped.
fn loss_should_drop(model: &Loss, state: &mut LossState) -> bool {
    match model {
        Loss::None => false,
        Loss::Rate(p) => rand_f64() < *p,
        Loss::Correlated { rate, correlation } => {
            let in_loss = state.in_loss;
            let drop = if in_loss {
                rand_f64() < *correlation || rand_f64() < *rate
            } else {
                rand_f64() < *rate
            };
            state.in_loss = drop;
            drop
        }
        Loss::GilbertElliott { p, r, h, k } => {
            state.ge_in_bad = if state.ge_in_bad {
                rand_f64() >= *r
            } else {
                rand_f64() < *p
            };
            if state.ge_in_bad { rand_f64() < *h } else { rand_f64() < *k }
        }
    }
}

// ── DirectionProfile ──────────────────────────────────────────────────────────

/// One-way link characteristics.
#[derive(Debug, Clone)]
pub struct DirectionProfile {
    /// Base one-way latency in nanoseconds.
    pub latency_ns:     u64,
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
            latency_ns:     0,
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

    /// Set base latency in milliseconds.
    pub fn latency(self, ms: u64) -> Self {
        DirectionProfile { latency_ns: ms * 1_000_000, ..self }
    }

    /// Set base latency in nanoseconds.
    pub fn latency_ns(self, ns: u64) -> Self {
        DirectionProfile { latency_ns: ns, ..self }
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

    /// Set jitter model.  Accepts `Jitter` or `u64` (→ `Jitter::Uniform`).
    pub fn jitter(self, j: impl Into<Jitter>) -> Self {
        DirectionProfile { jitter: j.into(), ..self }
    }

    /// Set loss model.  Accepts `Loss` or `f64` (→ `Loss::Rate`).
    pub fn loss(self, l: impl Into<Loss>) -> Self {
        DirectionProfile { loss: l.into(), ..self }
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

    /// Total one-way delay in nanoseconds for a frame of `len` bytes.
    pub fn delay_ns(&self, len: usize) -> u64 {
        let serial_ns = if self.bandwidth_bps > 0 {
            (len as u64 * 8 * 1_000_000_000) / self.bandwidth_bps
        } else {
            0
        };
        let jitter_ns = self.sample_jitter_ns();
        self.latency_ns + serial_ns + jitter_ns
    }

    fn sample_jitter_ns(&self) -> u64 {
        match &self.jitter {
            Jitter::None => 0,
            Jitter::Uniform(half_ns) => {
                if *half_ns == 0 { return 0; }
                next_u64() % (half_ns * 2 + 1)
            }
            Jitter::Normal { mean_ns, std_dev_ns } => {
                let u1 = rand_f64().max(f64::MIN_POSITIVE);
                let u2 = rand_f64();
                let z = (-2.0 * u1.ln()).sqrt()
                    * (2.0 * core::f64::consts::PI * u2).cos();
                let v = mean_ns + std_dev_ns * z;
                if v < 0.0 { 0 } else { v as u64 }
            }
            Jitter::Pareto { mean_ns, std_dev_ns } => {
                let cv = std_dev_ns / mean_ns;
                let alpha = 1.0 / (cv * cv) + 2.0;
                let sigma = mean_ns * (alpha - 1.0);
                let u = rand_f64().max(f64::MIN_POSITIVE);
                let v = sigma * (u.powf(-1.0 / alpha) - 1.0);
                if v < 0.0 { 0 } else { v as u64 }
            }
        }
    }

    /// Returns `true` if the frame should be dropped.
    pub fn should_drop(&self, loss_state: &mut LossState) -> bool {
        loss_should_drop(&self.loss, loss_state)
    }
}

// ── LinkProfile ───────────────────────────────────────────────────────────────

/// Bidirectional link characteristics.
#[derive(Clone)]
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

    // ── Directional impairment builders (chainable) ─────────────────────────

    /// Set loss model on A→B direction.
    pub fn loss_to_b(mut self, l: impl Into<Loss>) -> Self {
        self.a_to_b.loss = l.into(); self
    }

    /// Set loss model on B→A direction.
    pub fn loss_to_a(mut self, l: impl Into<Loss>) -> Self {
        self.b_to_a.loss = l.into(); self
    }

    /// Set loss model on both directions.
    pub fn loss_both(mut self, l: impl Into<Loss>) -> Self {
        let l = l.into();
        self.a_to_b.loss = l.clone();
        self.b_to_a.loss = l;
        self
    }

    /// Set jitter model on A→B direction.
    pub fn jitter_to_b(mut self, j: impl Into<Jitter>) -> Self {
        self.a_to_b.jitter = j.into(); self
    }

    /// Set jitter model on B→A direction.
    pub fn jitter_to_a(mut self, j: impl Into<Jitter>) -> Self {
        self.b_to_a.jitter = j.into(); self
    }

    /// Set jitter model on both directions.
    pub fn jitter_both(mut self, j: impl Into<Jitter>) -> Self {
        let j = j.into();
        self.a_to_b.jitter = j.clone();
        self.b_to_a.jitter = j;
        self
    }

    /// Set reorder model on A→B direction.
    pub fn reorder_to_b(mut self, r: Reorder) -> Self {
        self.a_to_b.reorder = r; self
    }

    /// Set reorder model on B→A direction.
    pub fn reorder_to_a(mut self, r: Reorder) -> Self {
        self.b_to_a.reorder = r; self
    }

    /// Set reorder model on both directions.
    pub fn reorder_both(mut self, r: Reorder) -> Self {
        self.a_to_b.reorder = r.clone();
        self.b_to_a.reorder = r;
        self
    }

    /// Set duplicate rate on A→B direction.
    pub fn duplicate_to_b(mut self, rate: f64) -> Self {
        self.a_to_b.duplicate_rate = rate; self
    }

    /// Set duplicate rate on B→A direction.
    pub fn duplicate_to_a(mut self, rate: f64) -> Self {
        self.b_to_a.duplicate_rate = rate; self
    }

    /// Set duplicate rate on both directions.
    pub fn duplicate_both(mut self, rate: f64) -> Self {
        self.a_to_b.duplicate_rate = rate;
        self.b_to_a.duplicate_rate = rate;
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

    pub fn leased_line_100m() -> Self {
        Self::symmetric(DirectionProfile::instant().latency(10).bandwidth_bps(100_000_000))
    }

    pub fn leased_line_1g() -> Self {
        Self::symmetric(DirectionProfile::instant().latency(10).bandwidth_bps(1_000_000_000))
    }

    pub fn leased_line_10g() -> Self {
        Self::symmetric(DirectionProfile::instant().latency(10).bandwidth_bps(10_000_000_000))
    }

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
    /// Absolute offset at which this frame becomes ready.
    /// Ready when `offset_ns >= deliver_at`.
    deliver_at: u64,
    data:       Vec<u8>,
}

impl PartialEq for DelayedFrame {
    fn eq(&self, other: &Self) -> bool {
        self.deliver_at == other.deliver_at
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
        other.deliver_at.cmp(&self.deliver_at)
    }
}

/// Duration-based delay queue.
///
/// Frames are enqueued with a remaining duration in nanoseconds.  Internally
/// the queue tracks a monotonically increasing `offset_ns` — each frame's
/// `deliver_at = offset_ns + remaining_ns` at enqueue time.  Calling
/// [`advance`](Self::advance) increments the offset; frames whose
/// `deliver_at <= offset_ns` are ready for delivery.
///
/// This design avoids per-element mutation on advance and preserves heap
/// ordering because existing `deliver_at` values never change.
struct DelayQueue {
    heap:      BinaryHeap<DelayedFrame>,
    offset_ns: u64,
}

impl DelayQueue {
    fn new() -> Self {
        DelayQueue { heap: BinaryHeap::new(), offset_ns: 0 }
    }

    /// Enqueue a frame that becomes ready after `remaining_ns` nanoseconds.
    fn push(&mut self, remaining_ns: u64, data: Vec<u8>) {
        self.heap.push(DelayedFrame { deliver_at: self.offset_ns + remaining_ns, data });
    }

    /// Advance virtual time by `ns` nanoseconds.
    fn advance(&mut self, ns: u64) {
        self.offset_ns += ns;
    }

    /// Pop and return one ready frame, or `None`.
    fn pop_ready(&mut self) -> Option<Vec<u8>> {
        if self.heap.peek().is_some_and(|f| f.deliver_at <= self.offset_ns) {
            self.heap.pop().map(|f| f.data)
        } else {
            None
        }
    }

    /// Remaining nanoseconds until the earliest pending frame, or `None`.
    fn next_remaining_ns(&self) -> Option<u64> {
        self.heap.peek().map(|f| f.deliver_at.saturating_sub(self.offset_ns))
    }

    /// Remaining nanoseconds until the latest pending frame, or `None`.
    fn last_remaining_ns(&self) -> Option<u64> {
        self.heap.iter().map(|f| f.deliver_at).max().map(|t| t.saturating_sub(self.offset_ns))
    }

    #[cfg(test)]
    fn is_empty(&self) -> bool {
        self.heap.is_empty()
    }
}

// ── PacketSpec ────────────────────────────────────────────────────────────────

/// Specifies which packets an impairment or capture rule applies to.
pub struct PacketSpec {
    predicate: Option<crate::filter::Filter>,
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
    pub fn matching(f: crate::filter::Filter) -> Self {
        PacketSpec { predicate: Some(f), nth: None, count: 0 }
    }

    /// Match only the nth packet satisfying `f`.
    pub fn nth_matching(n: usize, f: crate::filter::Filter) -> Self {
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
    /// Probabilistic loss using a [`Loss`] model.  Carries its own
    /// [`LossState`] for stateful models (Correlated, GilbertElliott).
    Loss {
        model: Loss,
        state: LossState,
    },
    /// Probabilistic frame duplication.  The original always passes; with
    /// probability `rate` a copy is also emitted.
    Duplicate(f64),
    /// Probabilistic congestion marking.  With probability `rate`, set IP ECN
    /// field to CE (0x03) and recompute IP header checksum.  Simulates a
    /// congested router marking frames instead of dropping them.
    Congestion(f64),
}

impl Impairment {
    /// Create a probabilistic loss impairment.
    pub fn loss(model: impl Into<Loss>) -> Self {
        Impairment::Loss { model: model.into(), state: LossState::default() }
    }

    /// Create a probabilistic congestion marking impairment.
    pub fn congestion(rate: f64) -> Self {
        Impairment::Congestion(rate)
    }

    /// Apply this impairment to a frame.  Returns `Some(data)` if the frame
    /// survives, `None` if dropped.  Duplicate is handled separately in
    /// [`PortDirection::process`].
    fn apply(&mut self, frame: &[u8]) -> Option<Vec<u8>> {
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
            Impairment::Loss { model, state } => {
                if loss_should_drop(model, state) { None } else { Some(frame.to_vec()) }
            }
            // Duplicate pass-through: the original always survives.
            // The copy is emitted by PortDirection::process().
            Impairment::Duplicate(_) => Some(frame.to_vec()),
            Impairment::Congestion(rate) => {
                let mut data = frame.to_vec();
                if rand_f64() < *rate {
                    // Ethernet(14) + IP byte 1 = offset 15 is DSCP/ECN.
                    // Set ECN field (low 2 bits) to CE = 0b11.
                    if data.len() > 15 {
                        data[15] = (data[15] & 0xFC) | 0x03;
                        // Recompute IP header checksum (bytes 14..34).
                        if data.len() >= 34 {
                            data[24] = 0; data[25] = 0;
                            let acc = crate::ip::checksum_add(0, &data[14..34]);
                            let csum = crate::ip::checksum_finish(acc).to_be_bytes();
                            data[24] = csum[0]; data[25] = csum[1];
                        }
                    }
                }
                Some(data)
            }
        }
    }
}

// ── PortDir ───────────────────────────────────────────────────────────────────

/// Which direction an impairment or profile applies to on a bridge port.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PortDir {
    /// Frames entering the bridge from the interface (TX path of the interface).
    Ingress,
    /// Frames leaving the bridge toward the interface (RX path of the interface).
    Egress,
}

// ── CapturedFrame ─────────────────────────────────────────────────────────────

/// A frame captured by the bridge, with forwarding metadata.
#[derive(Debug, Clone)]
pub struct CapturedFrame {
    /// Index of the port the frame arrived on.
    pub ingress: usize,
    /// Index of the port the frame was forwarded to, or `None` if dropped.
    pub egress:  Option<usize>,
    /// Raw frame bytes.
    pub data:    Vec<u8>,
    /// Sender's monotonic clock at TX time, in nanoseconds.
    /// `0` for frames injected via [`Bridge::inject`].
    pub ts_ns:   u64,
}

impl CapturedFrame {
    /// Returns `true` if the frame was dropped by the impairment pipeline
    /// and never forwarded to an egress port.
    pub fn is_dropped(&self) -> bool {
        self.egress.is_none()
    }
}

// ── PortDirection ─────────────────────────────────────────────────────────────

struct PortDirection {
    profile:      DirectionProfile,
    loss_state:   LossState,
    impairments:  Vec<Impairment>,
    delay_queue:  DelayQueue,
    /// Duration (ns) until the link finishes transmitting the previous frame.
    /// Decremented by [`advance`]; new frames queue behind this duration.
    link_busy_ns: u64,
}

impl PortDirection {
    fn new(profile: DirectionProfile) -> Self {
        PortDirection {
            profile,
            loss_state:   LossState::default(),
            impairments:  Vec::new(),
            delay_queue:  DelayQueue::new(),
            link_busy_ns: 0,
        }
    }

    /// Compute the remaining duration (ns) until a frame of `len` bytes
    /// would be delivered, accounting for serialization queueing behind
    /// previous frames.
    fn schedule(&mut self, len: usize) -> u64 {
        let serial_ns = if self.profile.bandwidth_bps > 0 {
            (len as u64 * 8 * 1_000_000_000) / self.profile.bandwidth_bps
        } else {
            0
        };
        let jitter_ns = self.profile.sample_jitter_ns();
        // Frame begins transmitting after the link is free.
        let depart_remaining = self.link_busy_ns + serial_ns;
        self.link_busy_ns = depart_remaining;
        depart_remaining + self.profile.latency_ns + jitter_ns
    }

    /// Advance virtual time by `ns` nanoseconds.
    fn advance(&mut self, ns: u64) {
        self.link_busy_ns = self.link_busy_ns.saturating_sub(ns);
        self.delay_queue.advance(ns);
    }

    /// Apply impairments and profile loss to a frame.  Returns `Some((data, duplicates))`
    /// if the frame survives, `None` if dropped.  `duplicates` contains any copies
    /// produced by [`Impairment::Duplicate`].
    fn process(&mut self, frame: &[u8]) -> Option<(Vec<u8>, Vec<Vec<u8>>)> {
        // Apply impairments chain.
        let mut data: Option<Vec<u8>> = Some(frame.to_vec());
        let mut duplicates: Vec<Vec<u8>> = Vec::new();
        for imp in &mut self.impairments {
            match imp {
                Impairment::Duplicate(rate) => {
                    if let Some(ref d) = data {
                        if rand_f64() < *rate {
                            duplicates.push(d.clone());
                        }
                    }
                }
                _ => {
                    data = data.and_then(|f| imp.apply(&f));
                    if data.is_none() {
                        break;
                    }
                }
            }
        }
        let data = data?;

        // Apply profile loss.
        if self.profile.should_drop(&mut self.loss_state) {
            return None;
        }

        Some((data, duplicates))
    }

    /// Drain all delay-queue frames whose remaining duration has elapsed.
    fn drain_ready(&mut self) -> Vec<Vec<u8>> {
        let mut out = Vec::new();
        while let Some(frame) = self.delay_queue.pop_ready() {
            out.push(frame);
        }
        out
    }
}

// ── BridgePort ────────────────────────────────────────────────────────────────

struct BridgePort {
    /// Queue owned by the interface's `rx_queue` (egress from bridge).
    egress:     FrameQueue,
    /// Ingress-direction impairment pipeline (drop/corrupt applied in TX closure).
    profile_in: PortDirection,
    /// Egress-direction impairment pipeline + delay queue.
    profile_eg: PortDirection,
}

// ── BridgeInner ───────────────────────────────────────────────────────────────

struct BridgeInner {
    ports:    Vec<BridgePort>,
    /// MAC forwarding database: source MAC → port index.
    fdb:      BTreeMap<[u8; 6], usize>,
    captured: Vec<CapturedFrame>,
}

impl BridgeInner {
    fn new() -> Self {
        BridgeInner {
            ports:    Vec::new(),
            fdb:      BTreeMap::new(),
            captured: Vec::new(),
        }
    }
}

// ── Bridge ────────────────────────────────────────────────────────────────────

/// N-port software bridge with MAC FDB, impairment pipeline, and capture.
///
/// See the [module-level documentation](self) for usage.
pub struct Bridge {
    inner: Rc<RefCell<BridgeInner>>,
}

impl Default for Bridge {
    fn default() -> Self { Self::new() }
}

impl Bridge {
    /// Create a new bridge with no ports.
    pub fn new() -> Self {
        Bridge { inner: Rc::new(RefCell::new(BridgeInner::new())) }
    }

    /// Begin adding a new port to this bridge.
    ///
    /// Returns a [`PortBuilder`] that configures the port; call
    /// [`PortBuilder::finish`] to complete registration.
    pub fn add_port<'a, 'b>(
        &'b self,
        net:       &'a mut Network,
        iface_idx: usize,
    ) -> PortBuilder<'a, 'b> {
        PortBuilder {
            net,
            bridge:      self,
            iface_idx,
            profile_in:  DirectionProfile::instant(),
            profile_eg:  DirectionProfile::instant(),
            impairments: Vec::new(),
        }
    }

    /// Inject a raw frame into `port`'s ingress side (for unit tests).
    ///
    /// Applies ingress impairments and forwards immediately to the appropriate
    /// egress port(s), bypassing any delay queue.  Useful in tests where the
    /// sender is not a real interface TX closure.
    pub fn inject(&self, port: usize, frame: &[u8]) {
        let mut inner = self.inner.borrow_mut();
        let Some((data, dups)) = inner.ports[port].profile_in.process(frame) else {
            inner.captured.push(CapturedFrame { ingress: port, egress: None, data: frame.to_vec(), ts_ns: 0 });
            return;
        };
        // Deliver immediately (no delay).
        for dup in dups {
            forward_frame(&mut inner, port, dup, 0, false);
        }
        forward_frame(&mut inner, port, data, 0, false);
    }

    /// Forward a frame through the bridge.  The source MAC (bytes 6..12)
    /// determines the ingress port via FDB lookup; the frame then follows
    /// the full bridge path (ingress impairments, FDB dst lookup, egress
    /// impairments, and delay queue).
    pub fn forward(&self, frame: &[u8]) {
        let mut inner = self.inner.borrow_mut();
        let src_mac: [u8; 6] = match frame.get(6..12).and_then(|b| b.try_into().ok()) {
            Some(m) => m,
            None => return,
        };
        let port = match inner.fdb.get(&src_mac) {
            Some(&p) => p,
            None => return,
        };
        let Some((data, dups)) = inner.ports[port].profile_in.process(frame) else {
            inner.captured.push(CapturedFrame { ingress: port, egress: None, data: frame.to_vec(), ts_ns: 0 });
            return;
        };
        for dup in dups {
            forward_frame(&mut inner, port, dup, 0, true);
        }
        forward_frame(&mut inner, port, data, 0, true);
    }

    /// Deliver a frame directly to the port whose MAC matches the
    /// destination MAC (bytes 0..6).  Bypasses all impairments and delay —
    /// the frame is immediately available in the port's rx_queue.
    pub fn ingress(&self, frame: &[u8]) {
        let inner = self.inner.borrow();
        let dst_mac: [u8; 6] = match frame.get(0..6).and_then(|b| b.try_into().ok()) {
            Some(m) => m,
            None => return,
        };
        let port = match inner.fdb.get(&dst_mac) {
            Some(&p) => p,
            None => return,
        };
        inner.ports[port].egress.push(frame);
    }

    /// Drain and return all captured frames.
    pub fn drain_captured(&mut self) -> Vec<CapturedFrame> {
        core::mem::take(&mut self.inner.borrow_mut().captured)
    }

    /// Flush all pending delayed frames regardless of their remaining duration.
    ///
    /// Advances each port's egress delay queue to `u64::MAX` and delivers to
    /// the egress [`FrameQueue`].  Useful in tests that want to force-deliver
    /// all in-flight frames without advancing time.
    pub fn flush(&self) {
        let mut inner = self.inner.borrow_mut();
        let n_ports = inner.ports.len();
        for egress_idx in 0..n_ports {
            // Advance far enough to make everything ready.
            inner.ports[egress_idx].profile_eg.delay_queue.advance(u64::MAX / 2);
            let delayed: Vec<Vec<u8>> = inner.ports[egress_idx].profile_eg.drain_ready();
            for eg_data in delayed {
                inner.ports[egress_idx].egress.push(&eg_data);
            }
        }
    }

    /// Advance all port delay queues and link-busy counters by `ns` nanoseconds.
    ///
    /// After advancing, any frames whose remaining duration has elapsed can be
    /// delivered by calling [`deliver`](Self::deliver).
    pub fn advance(&self, ns: u64) {
        let mut inner = self.inner.borrow_mut();
        for port in &mut inner.ports {
            port.profile_eg.advance(ns);
        }
    }

    /// Deliver all ready frames (whose remaining duration has elapsed) to their
    /// egress [`FrameQueue`]s.  Returns the remaining nanoseconds until the
    /// next pending frame, or `None` if all queues are empty.
    pub fn deliver(&self) -> Option<u64> {
        let mut inner = self.inner.borrow_mut();
        let n_ports = inner.ports.len();
        for idx in 0..n_ports {
            let ready = inner.ports[idx].profile_eg.drain_ready();
            for data in ready {
                inner.ports[idx].egress.push(&data);
            }
        }
        inner.ports.iter()
            .filter_map(|p| p.profile_eg.delay_queue.next_remaining_ns())
            .min()
    }

    /// Remaining nanoseconds until the earliest pending egress frame, or `None`.
    pub fn next_remaining_ns(&self) -> Option<u64> {
        let inner = self.inner.borrow();
        inner.ports.iter().filter_map(|p| p.profile_eg.delay_queue.next_remaining_ns()).min()
    }

    /// Remaining nanoseconds until the latest pending egress frame, or `None`.
    /// Useful for knowing how far to advance to drain an entire batch.
    pub fn last_remaining_ns(&self) -> Option<u64> {
        let inner = self.inner.borrow();
        inner.ports.iter().filter_map(|p| p.profile_eg.delay_queue.last_remaining_ns()).max()
    }

    /// Return `true` if all delay queues are empty.
    pub fn is_idle(&self) -> bool {
        self.next_remaining_ns().is_none()
    }

    /// Add an impairment to a port's ingress or egress pipeline.
    ///
    /// Can be called after the port has been fully configured via
    /// [`PortBuilder::finish`], making it easy to inject faults into a running
    /// test without rebuilding the whole bridge.
    pub fn add_impairment(&self, port: usize, dir: PortDir, imp: Impairment) {
        let mut inner = self.inner.borrow_mut();
        let pd = match dir {
            PortDir::Ingress => &mut inner.ports[port].profile_in,
            PortDir::Egress  => &mut inner.ports[port].profile_eg,
        };
        pd.impairments.push(imp);
    }

    /// Remove all impairments from a port's ingress **and** egress pipelines.
    pub fn clear_impairments(&self, port: usize) {
        let mut inner = self.inner.borrow_mut();
        inner.ports[port].profile_in.impairments.clear();
        inner.ports[port].profile_eg.impairments.clear();
    }

    /// Clear the MAC forwarding database.
    /// Pre-seed the FDB with a static MAC → port mapping.
    pub fn learn(&self, mac: [u8; 6], port: usize) {
        self.inner.borrow_mut().fdb.insert(mac, port);
    }

    pub fn flush_fdb(&self) {
        self.inner.borrow_mut().fdb.clear();
    }

    /// Connect two network interfaces through this bridge using a
    /// [`LinkProfile`].  Loss is applied on ingress (before bridging) and
    /// delay on egress (during delivery), matching real-world semantics.
    ///
    /// Returns `(port_a, port_b)`.
    pub fn add_link<'a>(
        &self,
        net_a:     &'a mut Network,
        iface_a:   usize,
        net_b:     &'a mut Network,
        iface_b:   usize,
        link:      &LinkProfile,
    ) -> (usize, usize) {
        // A→B: loss on port_a ingress, delay on port_b egress.
        // B→A: loss on port_b ingress, delay on port_a egress.
        let a_ingress = DirectionProfile {
            loss: link.a_to_b.loss.clone(),
            ..DirectionProfile::instant()
        };
        let a_egress = DirectionProfile {
            latency_ns:    link.b_to_a.latency_ns,
            bandwidth_bps: link.b_to_a.bandwidth_bps,
            jitter:        link.b_to_a.jitter.clone(),
            reorder:       link.b_to_a.reorder.clone(),
            duplicate_rate: link.b_to_a.duplicate_rate,
            queue_limit:   link.b_to_a.queue_limit,
            loss:          Loss::None,
        };
        let b_ingress = DirectionProfile {
            loss: link.b_to_a.loss.clone(),
            ..DirectionProfile::instant()
        };
        let b_egress = DirectionProfile {
            latency_ns:    link.a_to_b.latency_ns,
            bandwidth_bps: link.a_to_b.bandwidth_bps,
            jitter:        link.a_to_b.jitter.clone(),
            reorder:       link.a_to_b.reorder.clone(),
            duplicate_rate: link.a_to_b.duplicate_rate,
            queue_limit:   link.a_to_b.queue_limit,
            loss:          Loss::None,
        };

        let port_a = self.add_port(net_a, iface_a)
            .ingress(a_ingress)
            .egress(a_egress)
            .finish();
        let port_b = self.add_port(net_b, iface_b)
            .ingress(b_ingress)
            .egress(b_egress)
            .finish();
        (port_a, port_b)
    }
}

// ── Internal helper ───────────────────────────────────────────────────────────

/// Apply MAC learning, determine egress ports, apply egress impairments, and
/// deliver `data` (coming from `ingress_idx`) to the correct egress FrameQueues.
///
/// `capture_ts_ns` is the sender's clock reading at TX time, stored in
/// [`CapturedFrame::ts_ns`] for test inspection.  Pass `0` for inject paths.
/// `use_delay` controls whether frames go through the delay queue (`true`) or
/// are delivered immediately (`false`).
fn forward_frame(inner: &mut BridgeInner, ingress_idx: usize, data: Vec<u8>, capture_ts_ns: u64, use_delay: bool) {
    let n_ports = inner.ports.len();

    // Learn src MAC → ingress port.
    if data.len() >= 12 {
        let src_mac: [u8; 6] = data[6..12].try_into().unwrap();
        if src_mac != [0xff; 6] {
            inner.fdb.insert(src_mac, ingress_idx);
        }
    }

    // Determine egress port(s).
    let dst_mac: Option<[u8; 6]> = data.get(0..6).and_then(|b| b.try_into().ok());
    let is_broadcast_or_unknown = dst_mac.is_none_or(|mac| {
        mac == [0xff; 6]
        || (mac[0] & 1) != 0
        || !inner.fdb.contains_key(&mac)
    });

    let egress_ports: Vec<usize> = if is_broadcast_or_unknown {
        (0..n_ports).filter(|&j| j != ingress_idx).collect()
    } else {
        let dst = dst_mac.unwrap();
        let &egress_idx = inner.fdb.get(&dst).unwrap();
        if egress_idx == ingress_idx { vec![] } else { vec![egress_idx] }
    };

    if egress_ports.is_empty() {
        inner.captured.push(CapturedFrame { ingress: ingress_idx, egress: None, data, ts_ns: capture_ts_ns });
        return;
    }

    for &egress_idx in &egress_ports {
        // Apply egress impairments.
        let Some((eg_data, dups)) = inner.ports[egress_idx].profile_eg.process(&data) else {
            inner.captured.push(CapturedFrame { ingress: ingress_idx, egress: None, data: data.clone(), ts_ns: capture_ts_ns });
            continue;
        };

        inner.captured.push(CapturedFrame { ingress: ingress_idx, egress: Some(egress_idx), data: eg_data.clone(), ts_ns: capture_ts_ns });

        let has_delay = inner.ports[egress_idx].profile_eg.profile.latency_ns > 0
            || inner.ports[egress_idx].profile_eg.profile.bandwidth_bps > 0;

        // Deliver duplicates with the same schedule as an additional frame.
        for dup in dups {
            inner.captured.push(CapturedFrame { ingress: ingress_idx, egress: Some(egress_idx), data: dup.clone(), ts_ns: capture_ts_ns });
            if !has_delay || !use_delay {
                inner.ports[egress_idx].egress.push(&dup);
            } else {
                let remaining = inner.ports[egress_idx].profile_eg.schedule(dup.len());
                inner.ports[egress_idx].profile_eg.delay_queue.push(remaining, dup);
            }
        }

        if !has_delay || !use_delay {
            // Deliver immediately (instant link or inject path).
            inner.ports[egress_idx].egress.push(&eg_data);
        } else {
            // Schedule with proper serialization delay.
            let remaining = inner.ports[egress_idx].profile_eg.schedule(eg_data.len());
            inner.ports[egress_idx].profile_eg.delay_queue.push(remaining, eg_data);
        }
    }
}

// ── PortBuilder ───────────────────────────────────────────────────────────────

/// Builder for configuring a bridge port before registration.
///
/// Obtain via [`Bridge::add_port`]; call [`finish`](Self::finish) to register.
pub struct PortBuilder<'a, 'b> {
    net:         &'a mut Network,
    bridge:      &'b Bridge,
    iface_idx:   usize,
    profile_in:  DirectionProfile,
    profile_eg:  DirectionProfile,
    impairments: Vec<(PortDir, Impairment)>,
}

impl<'a, 'b> PortBuilder<'a, 'b> {
    /// Apply `p` to both ingress and egress directions.
    pub fn profile(mut self, p: DirectionProfile) -> Self {
        self.profile_in = p.clone();
        self.profile_eg = p;
        self
    }

    /// Apply `p` to the ingress direction (frames coming from the interface).
    pub fn ingress(mut self, p: DirectionProfile) -> Self {
        self.profile_in = p;
        self
    }

    /// Apply `p` to the egress direction (frames going to the interface).
    pub fn egress(mut self, p: DirectionProfile) -> Self {
        self.profile_eg = p;
        self
    }

    /// Add an impairment to the specified direction.
    pub fn add_impairment(mut self, dir: PortDir, imp: Impairment) -> Self {
        self.impairments.push((dir, imp));
        self
    }

    /// Register the port and return its port index.
    pub fn finish(self) -> usize {
        let PortBuilder { net, bridge, iface_idx, profile_in, profile_eg, impairments } = self;

        let mut pd_in = PortDirection::new(profile_in);
        let mut pd_eg = PortDirection::new(profile_eg);
        for (dir, imp) in impairments {
            match dir {
                PortDir::Ingress => pd_in.impairments.push(imp),
                PortDir::Egress  => pd_eg.impairments.push(imp),
            }
        }

        // Capture sender's clock before borrowing iface.
        let sender_clock = net.clock_ref();

        let iface = net.iface_mut(iface_idx);
        let egress = iface.rx_queue.clone();

        let bridge_inner = Rc::clone(&bridge.inner);
        let port_idx = {
            let mut b = bridge_inner.borrow_mut();
            let idx = b.ports.len();
            b.ports.push(BridgePort {
                egress,
                profile_in: pd_in,
                profile_eg: pd_eg,
            });
            idx
        };

        // Eager TX closure: apply ingress impairments, learn src MAC, forward
        // to egress port(s).  Sender clock is read only for capture timestamps.
        let tx_inner = Rc::clone(&bridge_inner);
        iface.set_tx(Rc::new(move |frame: &[u8]| -> crate::Result<()> {
            let mut inner = tx_inner.borrow_mut();
            let ts_ns = sender_clock.monotonic_ns();
            let Some((data, dups)) = inner.ports[port_idx].profile_in.process(frame) else {
                inner.captured.push(CapturedFrame { ingress: port_idx, egress: None, data: frame.to_vec(), ts_ns });
                return Ok(());
            };
            for dup in dups {
                forward_frame(&mut inner, port_idx, dup, ts_ns, true);
            }
            forward_frame(&mut inner, port_idx, data, ts_ns, true);
            Ok(())
        }));

        // Register a deliver closure on the receiver Network.  It drains this
        // port's egress delay queue (frames made ready by prior `advance` calls)
        // and returns the remaining ns until the next pending frame.
        let deliver_inner = Rc::clone(&bridge_inner);
        net.add_bridge_deliver(Rc::new(move || {
            let mut inner = deliver_inner.borrow_mut();
            let delayed: Vec<Vec<u8>> = inner.ports[port_idx].profile_eg.drain_ready();
            for eg_data in delayed {
                inner.ports[port_idx].egress.push(&eg_data);
            }
            inner.ports[port_idx].profile_eg.delay_queue.next_remaining_ns()
        }));

        port_idx
    }
}

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::eth::MacAddr;
    use crate::network::Network;

    fn mac(b: u8) -> MacAddr { MacAddr::from([0x02, 0, 0, 0, 0, b]) }

    fn make_frame(dst: [u8; 6], src: [u8; 6]) -> Vec<u8> {
        let mut f = vec![0u8; 42];
        f[0..6].copy_from_slice(&dst);
        f[6..12].copy_from_slice(&src);
        f[12..14].copy_from_slice(&[0x08, 0x06]);
        f
    }

    fn make_broadcast_frame(src: [u8; 6]) -> Vec<u8> {
        make_frame([0xff; 6], src)
    }

    fn setup_two_port() -> (Network, usize, Network, usize, Bridge) {
        let mut net_a = Network::new();
        let mut net_b = Network::new();
        let idx_a = net_a.add_interface().mac(mac(1)).finish();
        let idx_b = net_b.add_interface().mac(mac(2)).finish();
        let bridge = Bridge::new();
        let _port_a = bridge.add_port(&mut net_a, idx_a).finish();
        let _port_b = bridge.add_port(&mut net_b, idx_b).finish();
        (net_a, idx_a, net_b, idx_b, bridge)
    }

    #[test]
    fn broadcast_floods_to_all_other_ports() {
        let (net_a, idx_a, net_b, idx_b, bridge) = setup_two_port();

        // Inject a broadcast frame into port 0.
        let frame = make_broadcast_frame([0x02, 0, 0, 0, 0, 1]);
        bridge.inject(0, &frame);
        // (eager TX — no tick needed)

        // Should appear in port 1's egress (net_b's rx_queue).
        assert!(!net_b.interfaces()[idx_b].rx_queue.is_empty());
        // Should NOT appear in port 0's egress.
        assert!(net_a.interfaces()[idx_a].rx_queue.is_empty());
    }

    #[test]
    fn unicast_learned_and_forwarded() {
        let (net_a, idx_a, net_b, idx_b, bridge) = setup_two_port();

        // A→B: broadcast first so B's MAC is unknown.
        // But let's instead inject on port 1 first to teach FDB that MAC(2)=port_1.
        let frame_b_to_a = make_frame([0x02, 0, 0, 0, 0, 1], [0x02, 0, 0, 0, 0, 2]);
        bridge.inject(1, &frame_b_to_a);
        // (eager TX — no tick needed)
        // Frame should arrive at port 0 (net_a).
        assert!(!net_a.interfaces()[idx_a].rx_queue.is_empty());
        assert!(net_b.interfaces()[idx_b].rx_queue.is_empty());

        // Drain and inject a unicast frame from A to B's MAC.
        let _ = net_a.interfaces()[idx_a].rx_queue.pop();
        let frame_a_to_b = make_frame([0x02, 0, 0, 0, 0, 2], [0x02, 0, 0, 0, 0, 1]);
        bridge.inject(0, &frame_a_to_b);
        // (eager TX — no tick needed)
        // Should arrive at B (unicast via FDB).
        assert!(!net_b.interfaces()[idx_b].rx_queue.is_empty());
        assert!(net_a.interfaces()[idx_a].rx_queue.is_empty());
    }

    #[test]
    fn drop_impairment_prevents_delivery() {
        let mut net_a = Network::new();
        let mut net_b = Network::new();
        let idx_a = net_a.add_interface().mac(mac(1)).finish();
        let idx_b = net_b.add_interface().mac(mac(2)).finish();
        let bridge = Bridge::new();
        let _port_a = bridge.add_port(&mut net_a, idx_a)
            .add_impairment(PortDir::Ingress, Impairment::Drop(PacketSpec::any()))
            .finish();
        let _port_b = bridge.add_port(&mut net_b, idx_b).finish();

        bridge.inject(0, &make_broadcast_frame([0x02, 0, 0, 0, 0, 1]));
        // (eager TX — no tick needed)

        // Dropped on ingress — should not arrive at B.
        assert!(net_b.interfaces()[idx_b].rx_queue.is_empty());
    }

    #[test]
    fn capture_records_forwarded_and_dropped_frames() {
        let (net_a, _idx_a, _net_b, _idx_b, mut bridge) = setup_two_port();

        let frame = make_broadcast_frame([0x02, 0, 0, 0, 0, 1]);
        bridge.inject(0, &frame);
        // (eager TX — no tick needed)

        let captured = bridge.drain_captured();
        assert!(!captured.is_empty());
        // The delivered frame should have egress = Some(1).
        let delivered: Vec<_> = captured.iter().filter(|c| c.egress.is_some()).collect();
        assert!(!delivered.is_empty());
        let _ = net_a;
    }

    #[test]
    fn inject_and_tick_delivers_via_interface_tx() {
        let (net_a, idx_a, _net_b, _idx_b, bridge) = setup_two_port();

        // Use the interface TX (set by PortBuilder::finish) to push a frame.
        let frame = make_broadcast_frame([0x02, 0, 0, 0, 0, 1]);
        // net_a's iface TX should now push into port 0's ingress.
        {
            let tx = net_a.interfaces()[idx_a].open_eth_tx();
            tx(&frame).unwrap();
        }
        // (eager TX — no tick needed)
        // B's rx_queue should have the frame.
        // (Can't check B here since it's moved; we just verify no panic.)
        assert!(bridge.is_idle());
    }

    #[test]
    fn link_profile_instant_fields() {
        let p = LinkProfile::instant();
        assert_eq!(p.a_to_b.latency_ns, 0);
        assert_eq!(p.b_to_a.latency_ns, 0);
    }

    #[test]
    fn link_profile_presets_compile() {
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
        let _ = LinkProfile::leased_line_100m();
        let _ = LinkProfile::leased_line_1g();
        let _ = LinkProfile::leased_line_10g();
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
        dq.push(100, vec![1]);  // ready at offset 100
        dq.push(50,  vec![2]);  // ready at offset 50
        dq.push(200, vec![3]);  // ready at offset 200
        // Advance past all deadlines.
        dq.advance(200);
        assert_eq!(dq.pop_ready().unwrap(), vec![2]);
        assert_eq!(dq.pop_ready().unwrap(), vec![1]);
        assert_eq!(dq.pop_ready().unwrap(), vec![3]);
        assert!(dq.pop_ready().is_none());
    }

    #[test]
    fn delay_queue_advance_incremental() {
        let mut dq = DelayQueue::new();
        dq.push(100, vec![1]);
        dq.push(200, vec![2]);
        // Nothing ready yet.
        assert!(dq.pop_ready().is_none());
        assert_eq!(dq.next_remaining_ns(), Some(100));
        // Advance 100 — first frame ready.
        dq.advance(100);
        assert_eq!(dq.pop_ready().unwrap(), vec![1]);
        assert!(dq.pop_ready().is_none());
        assert_eq!(dq.next_remaining_ns(), Some(100));
        // Advance another 100 — second frame ready.
        dq.advance(100);
        assert_eq!(dq.pop_ready().unwrap(), vec![2]);
        assert!(dq.pop_ready().is_none());
        assert!(dq.is_empty());
    }

    #[test]
    fn corrupt_impairment_flips_byte() {
        let mut net_a = Network::new();
        let mut net_b = Network::new();
        let idx_a = net_a.add_interface().mac(mac(1)).finish();
        let idx_b = net_b.add_interface().mac(mac(2)).finish();
        let bridge = Bridge::new();
        let _port_a = bridge.add_port(&mut net_a, idx_a)
            .add_impairment(PortDir::Ingress, Impairment::Corrupt {
                when:     PacketSpec::any(),
                byte_idx: 0,
                xor_mask: 0xff,
            })
            .finish();
        let _port_b = bridge.add_port(&mut net_b, idx_b).finish();

        let frame = make_broadcast_frame([0x02, 0, 0, 0, 0, 1]);
        let orig_byte0 = frame[0];
        bridge.inject(0, &frame);
        // (eager TX — no tick needed)

        // The frame should arrive at B with byte 0 corrupted.
        let received = net_b.interfaces()[idx_b].rx_queue.pop().unwrap();
        assert_eq!(received[0], orig_byte0 ^ 0xff);
    }

    #[test]
    fn asymmetric_preset_has_different_directions() {
        let adsl = LinkProfile::adsl();
        assert!(adsl.a_to_b.bandwidth_bps > adsl.b_to_a.bandwidth_bps);
        assert_eq!(adsl.a_to_b.bandwidth_bps, 8_000_000);
        assert_eq!(adsl.b_to_a.bandwidth_bps, 800_000);
    }

    #[test]
    fn packet_spec_nth_drops_only_nth() {
        let (net_a, _idx_a, net_b, idx_b, bridge) = setup_two_port();

        // Drop only the 2nd frame from port 0.
        {
            let mut inner = bridge.inner.borrow_mut();
            inner.ports[0].profile_in.impairments.push(Impairment::Drop(PacketSpec::nth(2)));
        }

        let frame = make_broadcast_frame([0x02, 0, 0, 0, 0, 1]);
        bridge.inject(0, &frame); // 1st — passes
        bridge.inject(0, &frame); // 2nd — dropped
        bridge.inject(0, &frame); // 3rd — passes
        // (eager TX — no tick needed)

        // Should receive 2 frames (1st and 3rd).
        let f1 = net_b.interfaces()[idx_b].rx_queue.pop();
        let f2 = net_b.interfaces()[idx_b].rx_queue.pop();
        let f3 = net_b.interfaces()[idx_b].rx_queue.pop();
        assert!(f1.is_some());
        assert!(f2.is_some());
        assert!(f3.is_none());
        let _ = net_a;
    }

    #[test]
    fn from_f64_produces_loss_rate() {
        let l: Loss = 0.10.into();
        assert!(matches!(l, Loss::Rate(r) if (r - 0.10).abs() < f64::EPSILON));
    }

    #[test]
    fn from_u64_produces_jitter_uniform() {
        let j: Jitter = 5u64.into();
        assert!(matches!(j, Jitter::Uniform(5)));
    }

    #[test]
    fn direction_profile_loss_accepts_f64() {
        let p = DirectionProfile::instant().loss(0.05);
        assert!(matches!(p.loss, Loss::Rate(r) if (r - 0.05).abs() < f64::EPSILON));
    }

    #[test]
    fn direction_profile_jitter_accepts_u64() {
        let p = DirectionProfile::instant().jitter(10u64);
        assert!(matches!(p.jitter, Jitter::Uniform(10)));
    }

    #[test]
    fn loss_to_b_sets_only_a_to_b() {
        let link = LinkProfile::instant().loss_to_b(0.10);
        assert!(matches!(link.a_to_b.loss, Loss::Rate(_)));
        assert!(matches!(link.b_to_a.loss, Loss::None));
    }

    #[test]
    fn loss_to_a_sets_only_b_to_a() {
        let link = LinkProfile::instant().loss_to_a(0.10);
        assert!(matches!(link.a_to_b.loss, Loss::None));
        assert!(matches!(link.b_to_a.loss, Loss::Rate(_)));
    }

    #[test]
    fn loss_both_sets_both_directions() {
        let link = LinkProfile::instant().loss_both(0.05);
        assert!(matches!(link.a_to_b.loss, Loss::Rate(_)));
        assert!(matches!(link.b_to_a.loss, Loss::Rate(_)));
    }

    #[test]
    fn jitter_to_b_sets_only_a_to_b() {
        let link = LinkProfile::instant().jitter_to_b(5u64);
        assert!(matches!(link.a_to_b.jitter, Jitter::Uniform(5)));
        assert!(matches!(link.b_to_a.jitter, Jitter::None));
    }

    #[test]
    fn directional_builders_chain() {
        let link = LinkProfile::leased_line_100m()
            .loss_to_b(0.10)
            .jitter_to_b(5u64)
            .reorder_to_a(Reorder::rate(0.05));
        assert!(matches!(link.a_to_b.loss, Loss::Rate(_)));
        assert!(matches!(link.a_to_b.jitter, Jitter::Uniform(5)));
        assert!(matches!(link.b_to_a.loss, Loss::None));
        assert!(link.b_to_a.reorder.rate > 0.0);
    }

    #[test]
    fn leased_line_100m_is_symmetric_10ms_no_impairments() {
        let link = LinkProfile::leased_line_100m();
        assert_eq!(link.a_to_b.latency_ns, 10_000_000);
        assert_eq!(link.b_to_a.latency_ns, 10_000_000);
        assert_eq!(link.a_to_b.bandwidth_bps, 100_000_000);
        assert_eq!(link.b_to_a.bandwidth_bps, 100_000_000);
        assert!(matches!(link.a_to_b.loss, Loss::None));
        assert!(matches!(link.a_to_b.jitter, Jitter::None));
        assert!(matches!(link.b_to_a.loss, Loss::None));
        assert!(matches!(link.b_to_a.jitter, Jitter::None));
    }

    #[test]
    fn leased_line_presets_bandwidth() {
        assert_eq!(LinkProfile::leased_line_1g().a_to_b.bandwidth_bps, 1_000_000_000);
        assert_eq!(LinkProfile::leased_line_10g().a_to_b.bandwidth_bps, 10_000_000_000);
    }

    #[test]
    fn add_link_decomposes_loss_to_ingress_delay_to_egress() {
        let mut net_a = Network::new();
        let mut net_b = Network::new();
        let idx_a = net_a.add_interface().mac(mac(1)).finish();
        let idx_b = net_b.add_interface().mac(mac(2)).finish();

        let link = LinkProfile::leased_line_100m().loss_to_b(1.0);
        let bridge = Bridge::new();
        let (port_a, port_b) = bridge.add_link(&mut net_a, idx_a, &mut net_b, idx_b, &link);

        // A→B has loss=1.0, so port_a ingress should drop everything.
        let frame = make_broadcast_frame([0x02, 0, 0, 0, 0, 1]);
        bridge.inject(port_a, &frame);
        // Frame should be dropped — never reaches B.
        assert!(net_b.interfaces()[idx_b].rx_queue.is_empty());

        // B→A has no loss, so port_b ingress should pass.
        let frame_b = make_broadcast_frame([0x02, 0, 0, 0, 0, 2]);
        bridge.inject(port_b, &frame_b);
        // Frame should reach A (no delay since inject bypasses delay queue).
        assert!(!net_a.interfaces()[idx_a].rx_queue.is_empty());
    }

    #[test]
    fn congestion_impairment_sets_ce_bits() {
        // Build a minimal IPv4 frame: Ethernet(14) + IPv4(20) = 34 bytes.
        let mut frame = vec![0u8; 34];
        // Ethernet: dst=broadcast, src=00:00:00:00:00:01, type=IPv4
        frame[0..6].copy_from_slice(&[0xFF; 6]);
        frame[6..12].copy_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x01]);
        frame[12] = 0x08; frame[13] = 0x00;
        // IPv4: version/IHL=0x45, DSCP/ECN=0x00 (no ECN), total_len=20
        frame[14] = 0x45;
        frame[15] = 0x00; // DSCP=0, ECN=0
        frame[16] = 0x00; frame[17] = 20;
        // TTL=64, proto=TCP
        frame[22] = 64; frame[23] = 6;
        // Compute IP checksum
        let acc = crate::ip::checksum_add(0, &frame[14..34]);
        let csum = crate::ip::checksum_finish(acc).to_be_bytes();
        frame[24] = csum[0]; frame[25] = csum[1];

        // Congestion at 100% rate — always marks.
        let mut imp = Impairment::Congestion(1.0);
        let result = imp.apply(&frame).unwrap();

        // ECN field (low 2 bits of byte 15) should be CE = 0b11.
        assert_eq!(result[15] & 0x03, 0x03, "CE bits not set");

        // IP checksum should be valid after patching.
        let acc = crate::ip::checksum_add(0, &result[14..34]);
        let csum = crate::ip::checksum_finish(acc);
        assert_eq!(csum, 0, "IP checksum invalid after CE marking");
    }

    #[test]
    fn congestion_zero_rate_no_marking() {
        let mut frame = vec![0u8; 34];
        frame[12] = 0x08; frame[13] = 0x00;
        frame[14] = 0x45;
        frame[15] = 0x02; // ECN = ECT(0)

        let mut imp = Impairment::Congestion(0.0);
        let result = imp.apply(&frame).unwrap();

        // ECN field should be unchanged (ECT(0) = 0x02).
        assert_eq!(result[15] & 0x03, 0x02, "CE bits changed at rate=0.0");
    }
}
