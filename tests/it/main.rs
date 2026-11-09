//! The crate's integration tests in one binary.
//!
//! Every former `tests/<name>.rs` is a module here, so a warm edit loop links one test
//! executable instead of one per file. The test names keep their module prefix
//! (`it::<name>::<test>`). `tests/common` stays at its path because the library
//! (`src/lib.rs` and examples compile it with `#[path]`); this binary includes it the
//! same way. `records`, `network`, `adversarial` and `rpc` also run on wasm32, while the
//! other modules are native-only (see the cfg gates in `main.rs`).
mod adversarial;
#[path = "../common/mod.rs"]
mod common;
#[cfg(not(target_arch = "wasm32"))]
mod conformance;
#[cfg(not(target_arch = "wasm32"))]
mod envelope;
#[cfg(not(target_arch = "wasm32"))]
mod exact_publication;
mod network;
#[cfg(not(target_arch = "wasm32"))]
mod original_publication;
#[cfg(not(target_arch = "wasm32"))]
mod peers;
mod records;
mod rpc;
#[cfg(not(target_arch = "wasm32"))]
mod runtime;
#[cfg(not(target_arch = "wasm32"))]
mod watches;
