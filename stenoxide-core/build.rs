//! Build script for `stenoxide-core`.
//!
//! This script is intentionally passive. The only work it will ever perform is
//! compiling and linking the external libsdc++ Syndrome-Trellis Codes library,
//! and that step is gated behind the `ffi-stc` feature.
//!
//! Until PROMPT 6 introduces the STC FFI wrapper, `ffi-stc` must remain
//! disabled and this script must be a no-op: enabling it early would make the
//! build depend on a `LIBSDC_PATH` that does not exist yet.

fn main() {
    // Enable in PROMPT 6, once libsdc++ is available.
    // #[cfg(feature = "ffi-stc")]
    // compile_libsdc();
}
