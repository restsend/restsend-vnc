//! Send-path flow control helpers.
//!
//! RFB is transmitted over a single TCP stream. The old code bounded the
//! number of queued messages (8 x up to 1 MB) which, on a slow link, meant
//! seconds of latency before the pusher noticed and started dropping frames.
//! Here we bound *bytes in flight* instead, so the pusher stops diffing and
//! encoding as soon as the writer falls behind; the next diff naturally
//! coalesces all intermediate desktop changes.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

/// Tracks bytes handed to the writer but not yet written to the socket.
pub struct ByteBudget {
    limit: usize,
    in_flight: AtomicUsize,
}

impl ByteBudget {
    pub fn new(limit: usize) -> Self {
        ByteBudget {
            limit: limit.max(1),
            in_flight: AtomicUsize::new(0),
        }
    }

    pub fn in_flight(&self) -> usize {
        self.in_flight.load(Ordering::Relaxed)
    }

    pub fn has_capacity(&self) -> bool {
        self.in_flight() < self.limit
    }

    /// Reserves `bytes`; fails when the writer is already at the limit.
    pub fn try_reserve(&self, bytes: usize) -> bool {
        let mut current = self.in_flight.load(Ordering::Relaxed);
        loop {
            let next = current.saturating_add(bytes);
            if next > self.limit {
                return false;
            }
            match self.in_flight.compare_exchange_weak(
                current,
                next,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => return true,
                Err(actual) => current = actual,
            }
        }
    }

    /// Called by the writer once the bytes have been written (or dropped).
    pub fn release(&self, bytes: usize) {
        let _ = self
            .in_flight
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| {
                Some(v.saturating_sub(bytes))
            });
    }
}

/// Cursor-only updates bypass the (often 30 fps) frame interval: they carry a
/// few hundred bytes and are what makes the pointer feel local.
pub fn cursor_interval(frame_interval: Duration) -> Duration {
    frame_interval.min(Duration::from_millis(16))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn budget_reserves_and_releases() {
        let b = ByteBudget::new(100);
        assert!(b.try_reserve(60));
        assert!(b.try_reserve(40));
        assert!(!b.try_reserve(1));
        b.release(40);
        assert!(b.has_capacity());
        assert!(b.try_reserve(30));
        b.release(1_000); // never underflows
        assert_eq!(b.in_flight(), 0);
    }

    #[test]
    fn budget_parallel_reservations_do_not_overshoot() {
        let b = std::sync::Arc::new(ByteBudget::new(1000));
        let mut threads = Vec::new();
        for _ in 0..8 {
            let b = std::sync::Arc::clone(&b);
            threads.push(std::thread::spawn(move || {
                for _ in 0..1000 {
                    if b.try_reserve(37) {
                        b.release(37);
                    }
                }
            }));
        }
        for t in threads {
            t.join().unwrap();
        }
        assert!(b.in_flight() <= 1000);
    }

    #[test]
    fn cursor_interval_caps_at_60hz() {
        assert_eq!(
            cursor_interval(Duration::from_millis(33)),
            Duration::from_millis(16)
        );
        assert_eq!(
            cursor_interval(Duration::from_millis(8)),
            Duration::from_millis(8)
        );
    }
}
