# OpenShell protocol provenance

The QueryKnight OpenShell gRPC contract is sourced from the official NVIDIA/OpenShell repository at tag `v0.1.2`, commit `6648bd0c290efbc41ba131ee9831ee45cd431f94`.

Imported protocol inputs (both files are unchanged from the tagged upstream source):

| File | SHA-256 | License |
|---|---|---|
| `crates/qk-openshell/proto/extension.proto` | `60f28ee9dc846d41152f4db7e82a439c78d024786efaceb464900d1d1ad129ad` | Apache-2.0 |
| `crates/qk-openshell/proto/supervisor_middleware.proto` | `bee96ac940303d8a7530e6e2283a98077bb428a05ef610b51d018ea18377bebd` | Apache-2.0 |

The imported files retain their upstream SPDX copyright and Apache-2.0 headers. No OpenShell implementation code is vendored here, and this note does not change QueryKnight's project license.

Regenerate the Rust client/server bindings and descriptor set with the checked-in vendored compiler/build dependencies:

```sh
cargo build -p qk-openshell
cargo test -p qk-openshell --test proto_compat
```

`crates/qk-openshell/build.rs` uses `protoc-bin-vendored` and `tonic-prost-build`; `proto_compat` pins the complete generated descriptor-set SHA-256 (`180fc997b62f8162432f0206232b935f86dcb557e5f42c7980ff9caad39877a3`) as well as its wire-level RPC, field, and enum contract.
