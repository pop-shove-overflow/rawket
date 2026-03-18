/// Monotonic-clock timer list.
///
/// Timers are kept in ascending order of absolute deadline so that the
/// next-to-fire timer is always at index 0.  [`Timers::update`] should be
/// called on every iteration of the application's main loop; it returns the
/// nanoseconds until the next timer fires, suitable for use as a `ppoll(2)`
/// timeout.
use alloc::{boxed::Box, vec::Vec};

// ── Clock (production) ───────────────────────────────────────────────────────

#[cfg(not(feature = "test-internals"))]
#[derive(Clone, Default)]
pub struct Clock;

#[cfg(not(feature = "test-internals"))]
impl Clock {
    pub fn new() -> Self { Clock }

    /// Monotonic time in nanoseconds (`CLOCK_MONOTONIC`).  Never goes
    /// backwards and is unaffected by wall-clock adjustments.
    pub fn monotonic_ns(&self) -> u64 {
        let mut ts = libc::timespec { tv_sec: 0, tv_nsec: 0 };
        unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) };
        ts.tv_sec as u64 * 1_000_000_000 + ts.tv_nsec as u64
    }
    /// Monotonic time in milliseconds (`CLOCK_MONOTONIC`).
    pub fn monotonic_ms(&self) -> u64 { self.monotonic_ns() / 1_000_000 }
    /// Wall-clock time in nanoseconds since the Unix epoch (`CLOCK_REALTIME`).
    pub fn wall_clock_ns(&self) -> u64 {
        let mut ts = libc::timespec { tv_sec: 0, tv_nsec: 0 };
        unsafe { libc::clock_gettime(libc::CLOCK_REALTIME, &mut ts) };
        ts.tv_sec as u64 * 1_000_000_000 + ts.tv_nsec as u64
    }
    /// Wall-clock time in milliseconds since the Unix epoch (`CLOCK_REALTIME`).
    pub fn wall_clock_ms(&self) -> u64 { self.wall_clock_ns() / 1_000_000 }
}

// ── Clock (test-internals) ───────────────────────────────────────────────────

#[cfg(feature = "test-internals")]
use alloc::rc::Rc;
#[cfg(feature = "test-internals")]
use core::cell::Cell;

#[cfg(feature = "test-internals")]
struct ClockInner {
    /// Signed nanosecond offset added to every raw clock read.
    offset_ns:           Cell<i64>,
    paused:              Cell<bool>,
    /// Monotonic time (ns) captured at the moment `pause()` was called.
    frozen_monotonic_ns: Cell<u64>,
    /// Wall time (ns) captured at the moment `pause()` was called.
    frozen_wall_ns:      Cell<u64>,
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
                offset_ns:           Cell::new(0),
                paused:              Cell::new(false),
                frozen_monotonic_ns: Cell::new(0),
                frozen_wall_ns:      Cell::new(0),
            }),
        }
    }
}

#[cfg(feature = "test-internals")]
impl Clock {
    pub fn new() -> Self { Self::default() }

    /// Create a clock that starts at virtual time 0 (independent of the OS
    /// monotonic clock).  This is useful in deterministic tests where all
    /// timestamps should begin at 0 and advance only via explicit `advance_*`
    /// calls or natural code execution.
    pub fn zeroed() -> Self {
        let raw_ns = Self::raw_monotonic_ns();
        // offset = -(raw_ns) so that raw_ns + offset = 0 initially.
        Clock {
            inner: Rc::new(ClockInner {
                offset_ns:           Cell::new(-(raw_ns as i64)),
                paused:              Cell::new(false),
                frozen_monotonic_ns: Cell::new(0),
                frozen_wall_ns:      Cell::new(0),
            }),
        }
    }

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

    pub fn monotonic_ns(&self) -> u64 {
        if self.inner.paused.get() {
            self.inner.frozen_monotonic_ns.get()
        } else {
            let raw = Self::raw_monotonic_ns();
            (raw as i64 + self.inner.offset_ns.get()) as u64
        }
    }
    pub fn monotonic_ms(&self) -> u64 { self.monotonic_ns() / 1_000_000 }

    pub fn wall_clock_ns(&self) -> u64 {
        if self.inner.paused.get() {
            self.inner.frozen_wall_ns.get()
        } else {
            let raw = Self::raw_wall_clock_ns();
            (raw as i64 + self.inner.offset_ns.get()) as u64
        }
    }
    pub fn wall_clock_ms(&self) -> u64 { self.wall_clock_ns() / 1_000_000 }

    /// Advance apparent time by `ns` nanoseconds.
    pub fn advance_ns(&self, ns: i64) {
        if self.inner.paused.get() {
            let m = self.inner.frozen_monotonic_ns.get();
            let w = self.inner.frozen_wall_ns.get();
            self.inner.frozen_monotonic_ns.set((m as i64 + ns) as u64);
            self.inner.frozen_wall_ns.set((w as i64 + ns) as u64);
        } else {
            self.inner.offset_ns.set(self.inner.offset_ns.get() + ns);
        }
    }

    /// Advance apparent time by `us` microseconds.
    pub fn advance_us(&self, us: i64) {
        self.advance_ns(us * 1_000);
    }

    /// Advance apparent time by `ms` milliseconds.
    pub fn advance_ms(&self, ms: i64) {
        self.advance_ns(ms * 1_000_000);
    }

    /// Freeze time: subsequent calls to `monotonic_ms` / `wall_clock_ms`
    /// return the apparent time at the moment of this call until [`resume`]
    /// is called.
    pub fn pause(&self) {
        if !self.inner.paused.get() {
            self.inner.frozen_monotonic_ns.set(self.monotonic_ns());
            let raw = Self::raw_wall_clock_ns();
            self.inner.frozen_wall_ns.set((raw as i64 + self.inner.offset_ns.get()) as u64);
            self.inner.paused.set(true);
        }
    }

    /// Resume real-time progression from the current frozen time.
    ///
    /// Adjusts the offset so that the apparent time immediately after resume
    /// matches the frozen time at the moment of the last [`pause`].
    pub fn resume(&self) {
        if self.inner.paused.get() {
            let frozen_ns = self.inner.frozen_monotonic_ns.get();
            let raw_ns = Self::raw_monotonic_ns();
            self.inner.offset_ns.set(frozen_ns as i64 - raw_ns as i64);
            self.inner.paused.set(false);
        }
    }
}

// ── Deadline ──────────────────────────────────────────────────────────────────

/// An absolute CLOCK_MONOTONIC deadline in nanoseconds.
/// The sentinel `0` means disarmed; all real clock values are > 0.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default)]
pub(crate) struct Deadline(u64);

impl Deadline {
    /// Arm to fire `offset_ms` ms from `now_ns` (nanoseconds).
    pub(crate) fn from_now_ms(offset_ms: u64, now_ns: u64) -> Self {
        Self(now_ns + offset_ms * 1_000_000)
    }
    /// Arm at an absolute nanosecond deadline.
    pub(crate) fn arm_at(abs_ns: u64) -> Self {
        Self(abs_ns)
    }
    pub(crate) fn is_armed(self) -> bool { self.0 != 0 }
    /// True iff armed and `now_ns >= self`.
    pub(crate) fn is_expired(self, now_ns: u64) -> bool { self.0 != 0 && now_ns >= self.0 }
    pub(crate) fn disarm(&mut self) { self.0 = 0; }
    /// Re-arm to `now_ns + offset_ms * 1_000_000`; pass in `now_ns` to avoid extra syscall.
    pub(crate) fn arm_from_now_ms(&mut self, offset_ms: u64, now_ns: u64) {
        self.0 = now_ns + offset_ms * 1_000_000;
    }
    /// Re-arm to `now_ns + offset_ns`; pass in `now_ns` to avoid extra syscall.
    pub(crate) fn arm_from_now_ns(&mut self, offset_ns: u64, now_ns: u64) {
        self.0 = now_ns + offset_ns;
    }
    /// Remaining ns relative to `now_ns`; `None` if disarmed, `Some(0)` if expired.
    pub(crate) fn remaining_ns(self, now_ns: u64) -> Option<u64> {
        if self.0 == 0 { None } else { Some(self.0.saturating_sub(now_ns)) }
    }
    /// Absolute nanosecond deadline, or `None` if disarmed.
    pub(crate) fn abs_ns(self) -> Option<u64> {
        if self.0 == 0 { None } else { Some(self.0) }
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
    ///
    /// Use [`add_ns`](Self::add_ns) when sub-millisecond precision is needed.
    pub fn add(
        &mut self,
        duration_ms: u64,
        callback: impl FnOnce(&mut Timers) + 'static,
    ) -> TimerId {
        self.add_ns(duration_ms * 1_000_000, callback)
    }

    /// Schedule `callback` to be called after `duration_ns` nanoseconds.
    ///
    /// Identical to [`add`](Self::add) but accepts a nanosecond duration for
    /// sub-millisecond precision — useful for pacing callbacks and other
    /// high-rate timers on fast links.
    pub fn add_ns(
        &mut self,
        duration_ns: u64,
        callback: impl FnOnce(&mut Timers) + 'static,
    ) -> TimerId {
        let id  = TimerId(self.next_id);
        self.next_id += 1;
        let now = self.clock.monotonic_ns();
        let dl  = Deadline::arm_at(now + duration_ns);
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

    /// Fire any expired timers and return the nanoseconds until the next
    /// pending timer.
    ///
    /// Expired timers are removed from the list *before* their callbacks are
    /// invoked.  Each callback receives `&mut Timers`, so it may safely call
    /// [`add`](Self::add) to reschedule itself or schedule new timers.
    ///
    /// Returns `None` when there are no pending timers after firing.
    pub fn update(&mut self) -> Option<u64> {
        let now = self.clock.monotonic_ns();
        let n   = self.list.partition_point(|t| t.deadline <= Deadline(now));
        let cbs: Vec<_> = self.list.drain(..n).map(|t| t.callback).collect();
        for cb in cbs { cb(self); }
        // Re-read clock if any callback fired (they may have consumed wall time
        // or added short-duration timers whose remaining_ns would be overstated).
        let now = if n > 0 { self.clock.monotonic_ns() } else { now };
        self.list.first().map(|t| t.deadline.remaining_ns(now).unwrap_or(0))
    }

    /// Returns `true` if there are no pending timers.
    pub fn is_empty(&self) -> bool {
        self.list.is_empty()
    }

    /// Returns the number of pending timers.
    pub fn len(&self) -> usize {
        self.list.len()
    }

    /// Absolute nanosecond timestamp of the earliest pending timer, or `None`.
    /// Does **not** fire expired timers — use [`update`](Self::update) for that.
    pub fn next_deadline_abs_ns(&self) -> Option<u64> {
        self.list.first().map(|t| t.deadline.0)
    }

    /// Returns a reference to the clock driving this timer list.
    pub fn clock(&self) -> &Clock { &self.clock }
}
