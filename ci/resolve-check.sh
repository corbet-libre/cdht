#!/usr/bin/env bash
set -euo pipefail
: "${CI:?CI only}"
export CARGO_HTTP_USER_AGENT=records-ci
export CARGO_NET_GIT_FETCH_WITH_CLI=true
python3 .github/check-first-party.py --archive
cargo update
rustc --version
cargo --version
date -u +%FT%TZ
sha256sum Cargo.lock
# A dependency-only receipt, never runtime inputs or credentials. The orchestrator
# extracts the candidate without running Cargo or creating a second resolution.
printf '%s\n' 'CDHT_RESOLVED_LOCK_BEGIN'
base64 Cargo.lock
printf '%s\n' 'CDHT_RESOLVED_LOCK_END'
python3 .github/check-first-party.py --archive
