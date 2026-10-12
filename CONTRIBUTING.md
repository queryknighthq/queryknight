# Contributing to QueryKnight

QueryKnight is a deterministic SQL authorization/execution layer. It is an early
technical preview, and the security semantics are the product: a change that
weakens them is a defect even when every test still passes.

## Before you start

Open an issue describing the change if it touches policy evaluation, approval
binding, protocol handling, or anything under `docs/security-invariants.md`.
Small documentation and test fixes do not need that.

## Toolchain

- Rust 2021 edition. Developed and validated with `rustc`/`cargo` 1.94.1; no
  minimum supported Rust version is declared yet.
- No `rust-toolchain.toml` is committed, so a normal stable toolchain works.
  CI runs stable.
- Some integration scripts additionally need Docker, `jq`, `openssl`, `nc`,
  `python3`, and `z3` (see [the OpenShell demo](docs/openshell-postgres-demo.md)).

## Required quality commands

Run all of these before opening a pull request. CI runs the same set.

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo test --workspace --locked
cargo build --workspace --all-features --locked
scripts/check-rustls-provider.sh
```

The `--all-features` selection is required, not optional: workspace feature
unification differs from a single-crate build, and that is exactly how the
rustls `CryptoProvider` conflict appeared. `scripts/check-rustls-provider.sh`
guards that class of regression.

## Rules that are not negotiable

- **No security-semantic change without tests.** A change to policy evaluation,
  decision precedence, approval binding, redaction, or fail-closed behaviour
  must come with tests that fail before the change.
- **SQL and protocol changes need fail-closed tests.** New or changed protocol
  handling must prove that malformed, unknown, or unsupported input is refused
  rather than forwarded. Denial must not be reachable only through the happy
  path.
- **No silent downgrade.** TLS, transport, or authorization downgrades must fail
  closed. Do not add a fallback that turns a refusal into a plaintext or
  unguarded path.
- **Keep the inspection boundary visible.** The PostgreSQL frontend hop is
  plaintext by design; the backend hop is verified TLS. Do not describe or
  implement one as the other.
- **Do not weaken a gate to make a run pass.** If a check cannot be satisfied,
  report it instead of relaxing the assertion.

## OpenShell compatibility

Compatibility targets **tagged** OpenShell releases, currently `v0.1.2`
(commit `6648bd0c290efbc41ba131ee9831ee45cd431f94`). Do not track `main`, and do
not add a compatibility claim for a release that has not been live-verified.
The matrix and the evidence for each surface live in
[`docs/openshell-compatibility.md`](docs/openshell-compatibility.md).

Imported OpenShell protocol material keeps its upstream SPDX headers and is
documented in [`third_party/openshell/README.md`](third_party/openshell/README.md).
Do not replace upstream attribution with project attribution.

## Live integration tests

These need a real environment and are not part of ordinary unit runs:

| Script | Needs |
|---|---|
| `scripts/test-postgres-tls.sh` | Docker; provisions an ephemeral PKI and two PostgreSQL 17 servers |
| `scripts/test-openshell-v0.1.2.sh` | Docker + `z3`; builds the OpenShell gateway from the pinned commit |
| `scripts/test-openshell-postgres-v0.1.2.sh` | the above, plus PostgreSQL 17; the flagship demo |

They are validated on macOS on Apple Silicon. Do not present them as validated
on another platform without running them there.

The daemon's embedded UI bundle has two gates, described in
[`third_party/queryknight-ui/README.md`](third_party/queryknight-ui/README.md):
a public manifest check that every checkout and CI run executes, and an
owner-only correspondence check that is skipped when the private UI source is
unavailable.

## License

QueryKnight is licensed under Apache-2.0 (see [`LICENSE`](LICENSE)).

By submitting a contribution you agree that it is licensed under the same
terms, per section 5 of the Apache License. There is no separate contributor
license agreement and no copyright assignment.
