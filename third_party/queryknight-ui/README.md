# Vendored UI bundle provenance and licensing

`crates/qk-daemon/ui/` is a committed production build of the QueryKnight
browser UI. The daemon embeds it at compile time, so the binary serves the SPA
without any asset-path discovery or runtime frontend toolchain.

## Licensing

- The committed files under `crates/qk-daemon/ui/` are licensed as part of this
  repository under **Apache-2.0**.
- They are generated from the **separately maintained**
  `../queryknight-ts/apps/ui` application.
- **This does not relicense that application.** The `queryknight-ts` repository
  remains proprietary under its own existing license; only this build output is
  distributed here, under this repository's license.
- The sibling's proprietary license text is deliberately **not** copied into
  this repository, because it does not apply to any file here.

Files:

| File | Notes |
|---|---|
| `ui/index.html` | Vite build output (SPA shell) |
| `ui/assets/index-*.js` | Vite build output (hash-named) |
| `ui/assets/index-*.css` | Vite build output (hash-named) |

The bundle carries no version marker of its own; the daemon reports the product
version from its own crate metadata.

## Which check verifies what

Two independent gates, with different inputs and different owners
(`crates/qk-daemon/tests/ui_freshness.rs`):

| Check | Runs where | Verifies |
|---|---|---|
| `bundle_matches_pinned_manifest` | **public** — every checkout and every CI run; needs no other repository | the committed bundle is byte-for-byte the reviewed one. Compares the file set and each SHA-256 against the pinned `crates/qk-daemon/ui.sha256`. A stale, truncated, or hand-edited bundle fails here |
| `bundle_matches_private_source_build` | **owner/developer only** — skipped when the proprietary checkout or its `node_modules` is absent | the committed bundle still corresponds to the current private source. Rebuilds `apps/ui` with Vite and byte-compares the result |

A standalone public checkout therefore never needs the proprietary sibling:
`cargo build`, `cargo test`, and public CI all pass without it, and only the
second check skips. The first check cannot be skipped and is what stops a stale
bundle from being merged unnoticed.

Only the owner-side check can detect that the private source has moved on while
the bundle has not been re-exported. Run it from a development environment that
has `queryknight-ts` checked out and its frontend dependencies installed (or
point `QUERYKNIGHT_TS_DIR` at that checkout):

```sh
cargo test -p qk-daemon --test ui_freshness
```

## Re-exporting the bundle

When the private UI changes, re-export and re-pin together, from the bundle
root:

```sh
# 1. rebuild apps/ui in ../queryknight-ts and copy its dist/ over ui/
# 2. re-pin the manifest
cd crates/qk-daemon
find ui -type f | LC_ALL=C sort | xargs shasum -a 256 > ui.sha256
```

`crates/qk-daemon/build.rs` walks `ui/` and fails the build if the directory or
`index.html` is missing, so the bundle cannot silently disappear.
