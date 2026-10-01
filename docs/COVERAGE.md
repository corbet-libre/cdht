# Coverage contract

CI targets 100% of reachable production lines and branches. Stable Rust runs
the existing native and wasm checks. Nightly Rust is used only for LLVM branch
instrumentation, which currently requires it. Both jobs use the same resolved
Cargo.lock snapshot; all build and test commands after resolution use --locked.

The coverage job executes real tests with cargo-llvm-cov and retains the raw JSON
even when the gate fails. The checker compares integer covered/total counts for
both metrics; rounded percentages cannot pass. An empty report cannot pass.
The report excludes integration-test harness files under tests/, not production
code. No production source exclusions are currently approved.

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
the current wasm Clippy job is only a build check.
