# Coverage contract

CI targets 100% of reachable production lines and branches. Stable Rust runs
the existing native and wasm checks. Nightly Rust is used only for LLVM branch
instrumentation, which currently requires it. Both jobs use the same resolved
Cargo.lock snapshot; all build and test commands after resolution use --locked.

The coverage job executes real tests with cargo-llvm-cov and retains the raw JSON
even when the gate fails. The checker compares integer covered/total counts for
both metrics; rounded percentages cannot pass. An empty report cannot pass.
The report excludes integration-test harness files under tests/, not production
code. Only unchanged generated upstream Cap'n Proto output is excluded, as specified
in CONFORMANCE.md. The only handwritten proposals are the exact collision guards
documented below; their raw counters remain in all reports.

A failing gate is missing evidence, not permission to lower the threshold or
change domain behavior. Add meaningful failure and round-trip tests. Document
any genuinely unreachable defensive branch precisely before excluding it. Native
coverage does not establish browser execution; keep the actual wasm vectors.

First-party dependencies follow main. Their resolved full revisions remain in
Cargo.lock, with exactly one source per first-party crate. Dependabot maintains
committed snapshots; CI refreshes once per run and retains the tested snapshot.
Auto-merge requires protected main and successful substantive checks on the
exact current Dependabot head. It never executes PR code with write permissions.

## Scale and conformance

The real upstream Veilid conformance oracle remains a required CI job. Synthetic
population churn is not a conformance check and has been removed from the public
push path under the inherited resource policy. Run `cargo run --locked --release
--example churn` on Crow and retain its CSV with the tested commit. No new Crow
result or real-network scale claim is made by this configuration change. The
transport owner supplies the Crow execution path and actual wasm/adapter tests;
actual Wasm record/queue/network/RPC vectors execute independently of native coverage.

The strict source gate cross-checks LCOV counters with raw LLVM JSON and the
same-execution annotated source report. Deleted lines, missing branch locations,
duplicate files and inconsistent hit status fail independently of percentage
summaries. Generic source coverage is not coverage of every instantiation.

## Collision-hardening guards awaiting independent review

The exact source-bound manifest proposes **two lines and four branch outcomes**
for collision-hardening paths. These are computationally infeasible cryptographic
fixtures, not mathematically unreachable code and not tested success. Raw reports
retain all six counters. Acceptance requires review of these proposals.

`LocalBackend::create` indexes its private map by `Descriptor::key`, after real
signature/schema validation. That key is maintained BLAKE3 over fixed `VLD0`, the
32-byte owner and the exact compiled schema. All insertions use the same key
function. Reaching a different owner or schema at the same map key requires a
BLAKE3 collision; no public API can inject a different map index. The defensive
`WrongRecord` refusal and the two false equality outcomes remain in production.

`Question::answer` first calls `Descriptor::validate_for` for both the returned
and remembered descriptor against the same requested key. The following owner/
schema mismatch guard can then fire only with two distinct authenticated record
preimages of that same BLAKE3 digest. Its `WrongRecord` refusal and two true
inequality outcomes remain in production. Bad signatures, wrong requested keys,
missing descriptors and malformed nested wire pointers are reachable and remain
fully gated; none receives an exception.

No fake verifier, injected digest, fabricated map state or replacement hash is
used to manufacture a collision. Existing vectors use maintained real VLD0 and
BLAKE3, compare upstream-generated descriptors, and verify genuine alternate
valid signatures preserve the same record identity. The manifest binds every
proposal to the complete owning source, derivation source, real regression source
and exact Cargo.lock. Changed, moved, covered, missing or broadened exceptions
fail the shared source checker; its fourteen regression tests run in CI. Any
upstream/source change requires renewed evidence, not an automatic hash update.
