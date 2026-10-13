#!/usr/bin/env bash
set -euo pipefail
: "${CI:?CI only}"
command -v cargo-llvm-cov
rustc --version
cargo llvm-cov --version
export CARGO_BUILD_JOBS="${CI_JOBS:-2}"
cargo llvm-cov --locked --workspace --all-features --branch --no-cfg-coverage --no-cfg-coverage-nightly \
  --ignore-filename-regex '/tests/|/veilid_capnp.rs$' --json --output-path coverage.json
cargo llvm-cov report --branch --ignore-filename-regex '/tests/|/veilid_capnp.rs$' --lcov --output-path coverage.lcov
cargo llvm-cov report --branch --ignore-filename-regex '/tests/|/veilid_capnp.rs$' --text --output-path coverage.txt
python3 .github/test-source-coverage.py
python3 .github/check-source-coverage.py coverage.lcov coverage.json coverage.txt
