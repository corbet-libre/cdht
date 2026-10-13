#!/usr/bin/env bash
set -euo pipefail
: "${CI:?CI only}"
export CARGO_BUILD_JOBS="${CI_JOBS:-2}"
export CARGO_HTTP_USER_AGENT=records-ci
export CARGO_NET_GIT_FETCH_WITH_CLI=true
rustc --version
cargo --version
sha256sum Cargo.lock
python3 .github/check-first-party.py --archive
cargo fmt --all --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked --no-fail-fast
sha256sum Cargo.lock
