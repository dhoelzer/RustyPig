//! Literal port of helpers/event_gen.h — the EventGen<EVENT_MAX,
//! EVENT_NONE, GID> template (suppressed-event bitset + one-shot
//! `queue_event` through the DetectionEngine seam).
//!
//! Ground truth: /opt/data/snort3-src @ fe29cbe7403a. Row 17q uses it as
//! `FileEventGen = EventGen<EVENT__MAX_VALUE, EVENT__NONE, FILE_ID_GID>`
//! (file_flows.h:44); the fflows probe pins `gid=150 sid=1` firing
//! EXACTLY ONCE (the bitset suppression, event_gen.h:48).
//!
//! Deviation: C's `create_event` calls the static
//! `snort::DetectionEngine::queue_event(GID, (uint32_t)sid)` inline; the
//! port threads a `DetectionEventSink` parameter at the call (the same
//! witness boundary the donor stubs.cc:606 printed). REG_TEST-only
//! members (events_generated, none_found, get_raw, bitmask) compile out
//! in the harness build config and are not ported. `std::bitset<EVENT_MAX>`
//! -> Vec<bool> (the port never observes bitset order).

/// `snort::DetectionEngine::queue_event(gid, sid)` seam (the Detection
/// Engine monolith is a later row; the donor witness body prints
/// "DE queue_event gid=%u sid=%u").
pub trait DetectionEventSink {
    fn queue_event(&mut self, gid: u32, sid: u32);
}

/// `helpers/event_gen.h:27` `template <int EVENT_MAX, int EVENT_NONE, int GID> class EventGen`
pub struct EventGen<const EVENT_MAX: i32, const EVENT_NONE: i32, const GID: u32> {
    /// `std::bitset<EVENT_MAX> events_suppressed = 0;` (event_gen.h:66;
    /// lazily sized Vec<bool>, all-false == bitset 0).
    events_suppressed: Vec<bool>,
}

impl<const EVENT_MAX: i32, const EVENT_NONE: i32, const GID: u32> Default
    for EventGen<EVENT_MAX, EVENT_NONE, GID>
{
    /// `EventGen() = default;` — the suppressed bitset value-initializes
    /// to zeros.
    fn default() -> Self {
        EventGen { events_suppressed: vec![false; EVENT_MAX.max(0) as usize] }
    }
}

impl<const EVENT_MAX: i32, const EVENT_NONE: i32, const GID: u32>
    EventGen<EVENT_MAX, EVENT_NONE, GID>
{
    pub fn new() -> Self {
        Self::default()
    }

    /// `EventGen(const std::bitset<EVENT_MAX>& suppressed)` — pre-seeded
    /// suppression set. The port takes bytes of booleans; no pinned
    /// transcript uses this ctor (kept for shape).
    pub fn with_suppressed(suppressed: &[bool]) -> Self {
        let mut v = vec![false; EVENT_MAX.max(0) as usize];
        for (d, s) in v.iter_mut().zip(suppressed.iter()) {
            *d = *s;
        }
        EventGen { events_suppressed: v }
    }

    /// event_gen.h:34 `void create_event(int sid)` — transcribed
    /// literally, including the assert() preconditions (debug-only in C).
    pub fn create_event(&mut self, sid: i32, de: &mut dyn DetectionEventSink) {
        if sid == EVENT_NONE {
            return;
        }
        // assert((sid > 0) && (sid <= EVENT_MAX));
        debug_assert!((sid > 0) && (sid <= EVENT_MAX));
        // if (!events_suppressed[sid-1]) { queue_event(GID, sid); events_suppressed[sid-1] = true; }
        if !self.events_suppressed[(sid - 1) as usize] {
            de.queue_event(GID, sid as u32);
            self.events_suppressed[(sid - 1) as usize] = true;
            // #ifdef REG_TEST  events_generated[sid-1] = true;  (not built)
        }
    }

    /// event_gen.h:49 `void suppress_event(int sid)`
    pub fn suppress_event(&mut self, sid: i32) {
        // assert((sid > 0) && (sid <= EVENT_MAX));
        debug_assert!((sid > 0) && (sid <= EVENT_MAX));
        self.events_suppressed[(sid - 1) as usize] = true;
    }
}
