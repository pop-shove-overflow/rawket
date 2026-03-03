/// Monotonic-clock timer list.
///
/// Timers are kept in ascending order of absolute deadline so that the
/// next-to-fire timer is always at index 0.  [`Timers::update`] should be
/// called on every iteration of the application's main loop; it returns the
/// number of milliseconds until the next timer fires, which can be used
/// directly as the `poll(2)` timeout.
use alloc::{boxed::Box, vec::Vec};

// ── Time source ───────────────────────────────────────────────────────────────

/// Returns the current monotonic time in milliseconds.
///
/// `CLOCK_MONOTONIC` never goes backwards and is unaffected by wall-clock
/// adjustments, making it safe for elapsed-time arithmetic.
pub(crate) fn now_ms() -> u64 {
    let mut ts = libc::timespec { tv_sec: 0, tv_nsec: 0 };
    unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) };
    ts.tv_sec as u64 * 1_000 + ts.tv_nsec as u64 / 1_000_000
}

// ── Deadline ──────────────────────────────────────────────────────────────────

/// An absolute CLOCK_MONOTONIC deadline in milliseconds.
/// The sentinel `0` means disarmed; all real `now_ms()` values are > 0.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default)]
pub(crate) struct Deadline(u64);

impl Deadline {
    /// Arm to fire `offset_ms` ms from now (reads clock internally).
    pub(crate) fn from_now(offset_ms: u64) -> Self { Self(now_ms() + offset_ms) }
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

struct Timer {
    id:       TimerId,
    deadline: Deadline,
    callback: Box<dyn FnOnce(&mut Timers)>,
}

// ── Timers ────────────────────────────────────────────────────────────────────

/// A sorted list of pending timers driven by a monotonic clock.
pub struct Timers {
    list:    Vec<Timer>,
    next_id: u64,
}

impl Default for Timers {
    fn default() -> Self { Self::new() }
}

impl Timers {
    /// Create an empty timer list.
    pub fn new() -> Self {
        Timers { list: Vec::new(), next_id: 0 }
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
        let dl  = Deadline::from_now(duration_ms);
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
        let now = now_ms();
        let n   = self.list.partition_point(|t| t.deadline <= Deadline(now));
        let cbs: Vec<_> = self.list.drain(..n).map(|t| t.callback).collect();
        for cb in cbs { cb(self); }
        // Re-read clock if any callback fired (they may have consumed wall time
        // or added short-duration timers whose remaining_ms would be overstated).
        let now = if n > 0 { now_ms() } else { now };
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
}
