// Licensed under the Apache-2.0 license

// Bundle all the integration tests into a single binary for more efficient
// parallel execution

mod common;
mod ecdsa;
mod error_handling;
mod hmac;
mod integration_tests;
mod test_panic_missing;
