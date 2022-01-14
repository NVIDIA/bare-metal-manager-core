use crate::sync::atomic::{AtomicBool, Ordering::{AcqRel, Acquire, Release, Relaxed}};
use crate::thread::yield_now;

/// An atomic initializer: mutual exclusion during initialization.
pub struct Init {
    started: AtomicBool,
    done: AtomicBool
}

impl Init {
    /// A ready-to-init initializer.
    #[cfg(not(loom))]
    pub const fn new() -> Init {
        Init {
            started: AtomicBool::new(false),
            done: AtomicBool::new(false)
        }
    }

    /// A ready-to-init initializer.
    #[cfg(loom)]
    pub fn new() -> Init {
        Init {
            started: AtomicBool::new(false),
            done: AtomicBool::new(false)
        }
    }

    /// Returns true if initialization has completed without blocking. If this
    /// function returns false, it may be the case that initialization is
    /// currently in progress. If this function returns `true`, intialization is
    /// guaranteed to be completed.
    #[inline(always)]
    pub fn has_completed(&self) -> bool {
        self.done.load(Acquire)
    }

    /// Mark this initialization as complete, unblocking all threads that may be
    /// waiting.
    #[inline(always)]
    pub fn mark_complete(&self) {
        // If this is being called from outside of a `needed` block, we need to
        // ensure that `started` is `true` to avoid racing with (return `true`
        // to) future `needed` calls.
        self.started.store(true, Release);
        self.done.store(true, Release);
    }

    #[cold]
    #[inline(always)]
    fn try_to_need_init(&self) -> bool {
        // Quickly check if initialization has already started elsewhere.
        if self.started.load(Relaxed) {
            // If it has, wait until it's finished before returning. Finishing
            // is marked by calling `mark_complete`.
            while !self.done.load(Acquire) { yield_now() }
            return false;
        }

        // Try to be the first. If we lose (init_started is true), we wait.
        if self.started.compare_exchange(false, true, AcqRel, Relaxed).is_err() {
            // Another compare_and_swap won. Wait until they're done.
            while !self.done.load(Acquire) { yield_now() }
            return false;
        }

        true
    }

    /// Returns `true` if the caller needs to be be initialized. `false`
    /// otherwise. This function returns true to exactly one thread. If this
    /// function is called from multiple threads simulatenously, then the call
    /// blocks until `true` is returned to one thread. All other threads receive
    /// `false`.
    ///
    /// Blocking ends when the `mark_complete` function is called. That function
    /// _must_ be called by the thread that received `true` as a return value.
    #[inline(always)]
    pub fn needed(&self) -> bool {
        // Quickly check if initialization has finished, and return if so.
        if self.has_completed() {
            return false;
        }

        // We call a different function to attempt the intialiaztion to use
        // Rust's `cold` attribute to try let LLVM know that this is unlikely.
        self.try_to_need_init()
    }
}
