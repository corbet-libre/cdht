//! The crate's native integration tests in one binary.
//!
//! Every former `tests/<name>.rs` that the host runs is a module here, so a warm edit loop
//! links one test executable instead of one per file. The test names keep their module prefix
//! (`<name>::<test>`). The targets the wasm32 CI leg drives by name (`records`, `network`,
//! `adversarial`, `rpc`) stay separate, and `tests/common` stays at its path because both those
//! targets and the library (`src/lib.rs` `#[path]`) compile it.
#[path = "../common/mod.rs"]
mod common;
mod conformance;
mod envelope;
mod exact_publication;
mod original_publication;
mod peers;
mod runtime;
mod watches;
