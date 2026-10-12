#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Regression check: the workspace must resolve exactly one rustls
# CryptoProvider.
#
# rustls selects its process-level provider automatically only when exactly one
# of the `ring` / `aws-lc-rs` features is enabled. When both are active it
# panics at the first TLS use with "Could not automatically determine the
# process-level CryptoProvider from Rustls crate features" — and it does so in
# *every* rustls consumer in the workspace, including crates that never touched
# the dependency that introduced the second provider.
#
# Feature unification differs by selection, so `cargo test -p <one-crate>` can
# pass while `cargo test --workspace` fails. This check therefore inspects the
# widest graph (`--all-features`), not one crate's tree.
#
# The workspace provider is `ring` (pulled in by `tonic`'s `tls-ring`). Any
# dependency on a rustls-family crate must be declared with
# `default-features = false` plus an explicit `["ring", ...]` feature list.
# Separate crypto crates (`rcgen`, `jsonwebtoken`) using `aws_lc_rs` do not
# affect rustls provider selection.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

TREE="$(cargo tree -e features --all-features 2>/dev/null)"

aws_lc_rs="$(printf '%s\n' "$TREE" | grep -c 'rustls feature "aws_lc_rs"' || true)"
ring="$(printf '%s\n' "$TREE" | grep -c 'rustls feature "ring"' || true)"

if [[ "$aws_lc_rs" != "0" ]]; then
  echo "rustls provider conflict: aws-lc-rs is enabled ($aws_lc_rs references)." >&2
  echo "Declare every rustls-family dependency with default-features = false" >&2
  echo "and an explicit [\"ring\", ...] feature list." >&2
  printf '%s\n' "$TREE" | grep -B 3 'rustls feature "aws_lc_rs"' >&2 || true
  exit 1
fi

if [[ "$ring" == "0" ]]; then
  echo "rustls provider missing: ring is not enabled in the workspace graph." >&2
  exit 1
fi

echo "rustls provider: ring only (aws-lc-rs feature references: $aws_lc_rs, ring: $ring)"
