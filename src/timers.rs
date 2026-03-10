/// Monotonic-clock timer list.
///
/// Timers are kept in ascending order of absolute deadline so that the
/// next-to-fire timer is always at index 0.  [`Timers::update`] should be
/// called on every iteration of the application's main loop; it returns the
/// number of milliseconds until the next timer fires, which can be used
/// directly as the `poll(2)` timeout.
use alloc::{boxed::Box, vec::Vec};

// ── Wall-clock helper ─────────────────────────────────────────────────────────

/// Return the current CLOCK_MONOTONIC time in milliseconds.
///
/// Used by bridge.rs for delay-queue timestamps.
pub fn now_ms() -> u64 {
    let mut ts = libc::timespec { tv_sec: 0, tv_nsec: 0 };
    unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) };
    ts.tv_sec as u64 * 1_000 + ts.tv_nsec as u64 / 1_000_000
}

// ── Clock (production) ───────────────────────────────────────────────────────

#[cfg(not(feature = "test-internals"))]
#[derive(Clone, Default)]
pub struct Clock;

#[cfg(not(feature = "test-internals"))]
impl Clock {
    /// Monotonic time in milliseconds (`CLOCK_MONOTONIC`).  Never goes
    /// backwards and is unaffected by wall-clock adjustments.
    pub fn monotonic_ms(&self) -> u64 {
        let mut ts = libc::timespec { tv_sec: 0, tv_nsec: 0 };
        unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) };
        ts.tv_sec as u64 * 1_000 + ts.tv_nsec as u64 / 1_000_000
    }
    /// Wall-clock time in milliseconds since the Unix epoch (`CLOCK_REALTIME`).
    pub fn wall_clock_ms(&self) -> u64 {
        let mut ts = libc::timespec { tv_sec: 0, tv_nsec: 0 };
        unsafe { libc::clock_gettime(libc::CLOCK_REALTIME, &mut ts) };
        ts.tv_sec as u64 * 1_000 + ts.tv_nsec as u64 / 1_000_000
    }
}

// ── Clock (test-internals) ───────────────────────────────────────────────────

#[cfg(feature = "test-internals")]
use alloc::rc::Rc;
#[cfg(feature = "test-internals")]
use core::cell::Cell;

#[cfg(feature = "test-internals")]
struct ClockInner {
    /// Offset applied to raw CLOCK_MONOTONIC/CLOCK_REALTIME reads, in nanoseconds.
    offset_ns:        Cell<i64>,
    paused:           Cell<bool>,
    /// Frozen apparent time in nanoseconds (set on pause).
    frozen_monotonic: Cell<u64>,
    /// Frozen apparent wall-clock time in nanoseconds (set on pause).
    frozen_wall:      Cell<u64>,
}

#[cfg(feature = "test-internals")]
#[derive(Clone)]
pub struct Clock {
    inner: Rc<ClockInner>,
}

#[cfg(feature = "test-internals")]
impl Default for Clock {
    fn default() -> Self {
        Clock {
            inner: Rc::new(ClockInner {
                offset_ns:        Cell::new(0),
                paused:           Cell::new(false),
                frozen_monotonic: Cell::new(0),
                frozen_wall:      Cell::new(0),
            }),
        }
    }
}

#[cfg(feature = "test-internals")]
impl Clock {
    fn raw_monotonic_ns() -> u64 {
        let mut ts = libc::timespec { tv_sec: 0, tv_nsec: 0 };
        unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) };
        ts.tv_sec as u64 * 1_000_000_000 + ts.tv_nsec as u64
    }

    fn raw_wall_clock_ns() -> u64 {
        let mut ts = libc::timespec { tv_sec: 0, tv_nsec: 0 };
        unsafe { libc::clock_gettime(libc::CLOCK_REALTIME, &mut ts) };
        ts.tv_sec as u64 * 1_000_000_000 + ts.tv_nsec as u64
    }

    /// Returns the apparent monotonic time in nanoseconds.
    fn monotonic_ns(&self) -> u64 {
        if self.inner.paused.get() {
            self.inner.frozen_monotonic.get()
        } else {
            let raw = Self::raw_monotonic_ns();
            (raw as i64 + self.inner.offset_ns.get()) as u64
        }
    }

    /// Returns the apparent wall-clock time in nanoseconds.
    fn wall_clock_ns(&self) -> u64 {
        if self.inner.paused.get() {
            self.inner.frozen_wall.get()
        } else {
            let raw = Self::raw_wall_clock_ns();
            (raw as i64 + self.inner.offset_ns.get()) as u64
        }
    }

    pub fn monotonic_ms(&self) -> u64 {
        self.monotonic_ns() / 1_000_000
    }

    pub fn wall_clock_ms(&self) -> u64 {
        self.wall_clock_ns() / 1_000_000
    }

    /// Advance apparent time by `ns` nanoseconds.
    ///
    /// If paused, adjusts the frozen values directly; otherwise adjusts the
    /// offset applied to `clock_gettime` results.
    pub fn advance_ns(&self, ns: i64) {
        if self.inner.paused.get() {
            let m = self.inner.frozen_monotonic.get();
            let w = self.inner.frozen_wall.get();
            self.inner.frozen_monotonic.set((m as i64 + ns) as u64);
            self.inner.frozen_wall.set((w as i64 + ns) as u64);
        } else {
            let off = self.inner.offset_ns.get();
            self.inner.offset_ns.set(off + ns);
        }
    }

    /// Advance apparent time by `us` microseconds (`us * 1_000` nanoseconds).
    pub fn advance_us(&self, us: i64) {
        self.advance_ns(us * 1_000);
    }

    /// Advance apparent time by `ms` milliseconds (`ms * 1_000_000` nanoseconds).
    pub fn advance_ms(&self, ms: i64) {
        self.advance_ns(ms * 1_000_000);
    }

    /// Freeze time: subsequent calls to `monotonic_ms` / `wall_clock_ms`
    /// return the apparent time at the moment of this call until [`resume`]
    /// is called.
    pub fn pause(&self) {
        if !self.inner.paused.get() {
            self.inner.frozen_monotonic.set(self.monotonic_ns());
            self.inner.frozen_wall.set(self.wall_clock_ns());
            self.inner.paused.set(true);
        }
    }

    /// Resume real-time progression from the current frozen time.
    ///
    /// Adjusts the offset so that the apparent time immediately after resume
    /// matches the frozen time at the moment of the last [`pause`].
    pub fn resume(&self) {
        if self.inner.paused.get() {
            let frozen_m = self.inner.frozen_monotonic.get();
            let raw_m = Self::raw_monotonic_ns();
            self.inner.offset_ns.set(frozen_m as i64 - raw_m as i64);
            self.inner.paused.set(false);
        }
    }
}

// ── Deadline ──────────────────────────────────────────────────────────────────

/// An absolute CLOCK_MONOTONIC deadline in milliseconds.
/// The sentinel `0` means disarmed; all real clock values are > 0.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default)]
pub(crate) struct Deadline(u64);

impl Deadline {
    /// Arm to fire `offset_ms` ms from `now`.
    pub(crate) fn from_now(offset_ms: u64, now: u64) -> Self { Self(now + offset_ms) }
    pub(crate) fn is_armed(self) -> bool { self.0 != 0 }
    /// True iff armed and `now >= self`.
    pub(crate) fn is_expired(self, now: u64) -> bool { self.0 != 0 && now >= self.0 }
    pub(crate) fn disarm(&mut self) { self.0 = 0; }
    /// Re-arm to `now + offset_ms`; pass in `now` to avoid extra syscall.
    pub(crate) fn arm_from_now(&mut self, offset_ms: u64, now: u64) { self.0 = now + offset_ms; }
    /// Remaining ms relative to `now`; `None` if disarmed, `Some(0)` if expired.
    pub(crate) fn remaining_ms(self, now: u64) -> Option<u64> {
        if self.0 == 0 { None } else { Some(self.0.saturating_sub(now)) }
    }
}

// ── TimerId ───────────────────────────────────────────────────────────────────

/// An opaque handle returned by [`Timers::add`] that can be passed to
/// [`Timers::cancel`] to remove the timer before it fires.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TimerId(u64);

// ── Timer entry ───────────────────────────────────────────────────────────────

type TimerCallback = Box<dyn FnOnce(&mut Timers)>;

struct Timer {
    id:       TimerId,
    deadline: Deadline,
    callback: TimerCallback,
}

// ── Timers ────────────────────────────────────────────────────────────────────

/// A sorted list of pending timers driven by a [`Clock`].
pub struct Timers {
    list:    Vec<Timer>,
    next_id: u64,
    clock:   Clock,
}

impl Default for Timers {
    fn default() -> Self { Self::new(Default::default()) }
}

impl Timers {
    /// Create an empty timer list driven by `clock`.
    pub fn new(clock: Clock) -> Self {
        Timers { list: Vec::new(), next_id: 0, clock }
    }

    /// Schedule `callback` to be called after `duration_ms` milliseconds.
    ///
    /// The callback receives `&mut Timers`, allowing it to reschedule itself
    /// or add other timers before returning.  Returns a [`TimerId`] that can
    /// be passed to [`cancel`](Self::cancel) to remove the timer before it
    /// fires.
    pub fn add(
        &mut self,
        duration_ms: u64,
        callback: impl FnOnce(&mut Timers) + 'static,
    ) -> TimerId {
        let id  = TimerId(self.next_id);
        self.next_id += 1;
        let now = self.clock.monotonic_ms();
        let dl  = Deadline::from_now(duration_ms, now);
        let pos = self.list.partition_point(|t| t.deadline <= dl);
        self.list.insert(pos, Timer { id, deadline: dl, callback: Box::new(callback) });
        id
    }

    /// Cancel the timer identified by `id`, dropping its callback without
    /// calling it.  Returns `true` if the timer was found and removed,
    /// `false` if it had already fired or the id is otherwise unknown.
    pub fn cancel(&mut self, id: TimerId) -> bool {
        if let Some(pos) = self.list.iter().position(|t| t.id == id) {
            self.list.remove(pos);
            true
        } else {
            false
        }
    }

    /// Fire any expired timers and return the milliseconds until the next
    /// pending timer.
    ///
    /// Expired timers are removed from the list *before* their callbacks are
    /// invoked.  Each callback receives `&mut Timers`, so it may safely call
    /// [`add`](Self::add) to reschedule itself or schedule new timers.
    ///
    /// Returns `None` when there are no pending timers after firing.
    pub fn update(&mut self) -> Option<u64> {
        let now = self.clock.monotonic_ms();
        let n   = self.list.partition_point(|t| t.deadline <= Deadline(now));
        let cbs: Vec<_> = self.list.drain(..n).map(|t| t.callback).collect();
        for cb in cbs { cb(self); }
        // Re-read clock if any callback fired (they may have consumed wall time
        // or added short-duration timers whose remaining_ms would be overstated).
        let now = if n > 0 { self.clock.monotonic_ms() } else { now };
        self.list.first().map(|t| t.deadline.remaining_ms(now).unwrap_or(0))
    }

    /// Returns `true` if there are no pending timers.
    pub fn is_empty(&self) -> bool {
        self.list.is_empty()
    }

    /// Returns the number of pending timers.
    pub fn len(&self) -> usize {
        self.list.len()
    }

    /// Returns a reference to the clock driving this timer list.
    pub fn clock(&self) -> &Clock { &self.clock }
}
