//! Faithful Rust port of `time/stopwatch.h` (row 17j): the generic
//! `Stopwatch<Clock>` template. Literal transcription; state machine
//! pinned by the ORIGINAL upstream `[stopwatch]` suite (35
//! assertions, verbatim gate) plus an 11-line probe transcript for
//! the real-clock macro layer.
//!
//! - C default-initializes `start_time`: chrono `time_point`'s
//!   implicit default ctor value-initializes the duration to 0 in
//!   BOTH the TSC (`= CLOCK_ZERO`) and non-TSC builds — Rust seeds 0
//!   to match.
//! - `duration`/`time_point` are the i64 ns tick aliases from
//!   `clock_defs`.

use std::marker::PhantomData;

use super::clock_defs::{Clock, HrDuration, HrTime};

pub struct Stopwatch<C: Clock> {
    elapsed: HrDuration,
    running: bool,
    start_time: HrTime,
    // C++'s Clock template parameter is only used statically
    // (Clock::now()); Rust needs an explicit use site. Never read.
    #[allow(dead_code)]
    _clock: PhantomData<C>,
}

impl<C: Clock> Default for Stopwatch<C> {
    fn default() -> Self {
        // Stopwatch() : elapsed { DURA_ZERO }, running { false } { }
        Stopwatch { elapsed: 0, running: false, start_time: 0, _clock: PhantomData }
    }
}

impl<C: Clock> Stopwatch<C> {
    pub fn start(&mut self) {
        if self.running {
            return;
        }

        self.start_time = C::now();
        self.running = true;
    }

    pub fn stop(&mut self) {
        if !self.running {
            return;
        }

        // C `elapsed += get_delta()` is signed (well-defined under
        // gcc wrap); keep the wrap literal.
        self.elapsed = self.elapsed.wrapping_add(self.get_delta());
        self.running = false;
    }

    pub fn get(&self) -> HrDuration {
        if self.running {
            return self.elapsed.wrapping_add(self.get_delta());
        }

        self.elapsed
    }

    pub fn active(&self) -> bool {
        self.running
    }

    pub fn reset(&mut self) {
        self.running = false;
        self.elapsed = 0;
    }

    pub fn cancel(&mut self) {
        self.running = false;
    }

    pub fn get_start_time(&self) -> HrTime {
        self.start_time
    }

    // duration get_delta() const { return Clock::now() - start_time; }
    fn get_delta(&self) -> HrDuration {
        C::now().wrapping_sub(self.start_time)
    }
}
