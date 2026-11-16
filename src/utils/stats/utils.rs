//! Faithful Rust port of `utils/stats/utils.{h,cc}` (ground truth @
//! fe29cbe7403a): `should_render` gates whether a counter appears in a
//! renderer pass.
//!
//! Literal transcription; no deviations beyond language mechanics. The C
//! variant `is_zero` checks each alternative in order and also returns
//! true for the unreachable default arm; Rust's exhaustive match mirrors
//! every arm (a `Value` here is always one of the six alternatives).
use super::snapshot::{Counter, Value};

/// C `struct RenderOptions` (default include_zeros=false).
#[derive(Default, Clone, Copy)]
pub struct RenderOptions {
    // we could give the user the option to include zero-value counters
    // in the output
    pub include_zeros: bool,
}

/// C static `is_zero(const Counter&)`.
pub fn is_zero(counter: &Counter) -> bool {
    match &counter.value {
        Value::Mono => true,
        Value::Bool(v) => !*v,
        Value::I64(v) => *v == 0,
        Value::U64(v) => *v == 0,
        Value::F64(v) => *v == 0.0,
        Value::Str(v) => v.is_empty(),
    }
}

/// C `should_render` — with `include_zeros`, zeros render too.
pub fn should_render(counter: &Counter, options: &RenderOptions) -> bool {
    options.include_zeros || !is_zero(counter)
}
