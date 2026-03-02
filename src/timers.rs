/// Monotonic-clock timer list.
///
/// Timers are kept in ascending order of `remaining` milliseconds so that
/// the next-to-fire timer is always at index 0.  [`Timers::update`] should
/// be called on every iteration of the application's main loop; it returns
/// the number of milliseconds until the next timer fires, which can be used
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

// ── TimerId ───────────────────────────────────────────────────────────────────

/// An opaque handle returned by [`Timers::add`] that can be passed to
/// [`Timers::cancel`] to remove the timer before it fires.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TimerId(u64);

// ── Timer entry ───────────────────────────────────────────────────────────────

struct Timer {
    id: TimerId,
    /// Milliseconds remaining until this timer fires.
    remaining: u64,
    callback: Box<dyn FnOnce(&mut Timers)>,
}

// ── Timers ────────────────────────────────────────────────────────────────────

/// A sorted list of pending timers driven by a monotonic clock.
pub struct Timers {
    list: Vec<Timer>,
    /// Timestamp (ms) of the most recent [`update`](Self::update) call.
    last_tick: u64,
    next_id: u64,
}

impl Default for Timers {
    fn default() -> Self { Self::new() }
}

impl Timers {
    /// Create an empty timer list.  The internal clock is latched at
    /// construction time so the first `update()` call measures elapsed time
    /// from `new()`.
    pub fn new() -> Self {
        Timers { list: Vec::new(), last_tick: now_ms(), next_id: 0 }
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
        let id = TimerId(self.next_id);
        self.next_id += 1;
        // partition_point returns the first index where remaining > duration_ms,
        // so we insert after all timers with an equal or shorter deadline.
        let pos = self.list.partition_point(|t| t.remaining <= duration_ms);
        self.list.insert(pos, Timer { id, remaining: duration_ms, callback: Box::new(callback) });
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

    /// Advance all timers by the time elapsed since the last call, fire any
    /// that have expired, and return the milliseconds until the next pending
    /// timer.
    ///
    /// Expired timers are removed from the list *before* their callbacks are
    /// invoked.  Each callback receives `&mut Timers`, so it may safely call
    /// [`add`](Self::add) to reschedule itself or schedule new timers.
    ///
    /// Returns `None` when there are no pending timers after firing.
    pub fn update(&mut self) -> Option<u64> {
        let now = now_ms();
        let elapsed = now.saturating_sub(self.last_tick);
        self.last_tick = now;

        // Subtract elapsed from every timer.  saturating_sub keeps expired
        // timers at 0 rather than wrapping.  The sort order is preserved
        // because every element decreases by the same amount.
        for t in &mut self.list {
            t.remaining = t.remaining.saturating_sub(elapsed);
        }

        // All timers with remaining == 0 are at the front of the sorted list.
        let n_expired = self.list.partition_point(|t| t.remaining == 0);

        // Drain expired entries into a local Vec so that `self` (and therefore
        // `self.list`) is fully updated before any callback runs.  Each
        // callback then receives `&mut self`, allowing it to call `add` or
        // `cancel` without aliasing the drain iterator.
        let callbacks: Vec<_> =
            self.list.drain(..n_expired).map(|t| t.callback).collect();

        for cb in callbacks {
            cb(self);
        }

        self.list.first().map(|t| t.remaining)
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
