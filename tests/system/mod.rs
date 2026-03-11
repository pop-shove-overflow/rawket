// rawket system-test integration tests.
//
// Run: cargo test --features test-internals --test system
//
// Each test fn returns `TestResult`; returning `Err(e)` is reported as a
// failure with `e.msg` as the diagnostic.

mod assert;
mod capture;
mod harness;
mod packet;
mod tcp;

/// Shared result type for test functions.
pub type TestResult = Result<(), assert::TestFail>;


