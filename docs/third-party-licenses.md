# Third-party licenses

QueryKnight itself is licensed under **Apache-2.0** (see [`LICENSE`](../LICENSE)).
Third-party material keeps its own license and its own attribution; this
document records what is vendored, where it came from, and how a release-time
notice report is produced.

## Vendored and imported material

| Material | Location | License | Provenance |
|---|---|---|---|
| OpenShell extension + supervisor middleware protobuf definitions | `crates/qk-openshell/proto/` | Apache-2.0 (upstream NVIDIA) | [`third_party/openshell/README.md`](../third_party/openshell/README.md) — pinned to `v0.1.2` / `6648bd0c290efbc41ba131ee9831ee45cd431f94`, SHA-256 pinned, upstream SPDX headers retained |
| Embedded browser UI production bundle | `crates/qk-daemon/ui/` | Apache-2.0, as part of this repository | [`third_party/queryknight-ui/README.md`](../third_party/queryknight-ui/README.md) — a build of the separately maintained, proprietary `queryknight-ts` UI; that source is not relicensed by this repository |

No OpenShell implementation code is vendored, and no third-party source has been
relicensed. Upstream SPDX copyright headers are preserved verbatim; do not
replace them with project attribution.

## Rust dependencies

Dependencies are taken from crates.io and keep their own licenses. The direct
dependency graph is permissively licensed — `MIT`, `Apache-2.0`,
`MIT OR Apache-2.0`, or `Apache-2.0 OR ISC OR MIT` — with no copyleft or
non-redistributable terms. The workspace pins exact versions in `Cargo.lock`,
and CI builds with `--locked`.

The TLS stack is worth naming because it is the one place a provider choice is
observable: `rustls` with the `ring` provider, wired through
`tokio-rustls`/`tokio-postgres-rustls`. Every rustls-family dependency is
declared with `default-features = false` and an explicit `["ring", …]` feature
list, because enabling both `ring` and `aws-lc-rs` makes every rustls consumer
in the workspace panic at first TLS use. `scripts/check-rustls-provider.sh` is
the CI gate for that, and it inspects the `--all-features` graph.

## Generating a release-time notice report

There is no committed bundle of dependency license texts. Generate the report
at release time from the locked graph, and review the result before publishing
artifacts:

```sh
cargo install cargo-about --locked      # or cargo-deny, whichever the release
cargo about generate about.hbs -o third-party-notices.html
```

For a quick audit of the direct dependency set and its license expressions:

```sh
cargo metadata --format-version=1 --all-features \
  | jq -r '.packages[] | select(.license == null or (.license | test("MIT|Apache-2.0|BSD|ISC|Unicode|Zlib|CC0|0BSD|Unlicense") | not)) | "\(.name) \(.version) \(.license)"'
```

A non-empty result is the review list: confirm the license is compatible with
Apache-2.0 distribution before adding the dependency.

## NOTICE

No `NOTICE` file is included. Apache-2.0 section 4(d) only requires propagating
a NOTICE that upstream material actually carries, and the imported OpenShell
protocol definitions carry none — upstream `NVIDIA/OpenShell` at `v0.1.2` has no
`NOTICE` file, and the vendored files carry SPDX headers only. Inventing a
`NOTICE` would add attribution obligations rather than satisfy them. If a future
import brings material that ships a NOTICE, add one then, preserving the
upstream text.
