//! Frontend bundle gates for the daemon's embedded SPA (`ui/`).
//!
//! Two independent checks with different inputs and different owners. Neither
//! one rebuilds, installs, or downloads anything, and the first one is the only
//! one public CI needs.
//!
//! 1. [`bundle_matches_pinned_manifest`] — **public**. Needs no other
//!    repository. Every committed file under `ui/` must match the pinned
//!    `ui.sha256` manifest and the file set must match exactly, so a stale,
//!    truncated, or hand-edited bundle cannot be merged unnoticed.
//! 2. [`bundle_matches_private_source_build`] — **owner/developer only**.
//!    Rebuilds the SPA from the separately maintained, proprietary
//!    `queryknight-ts` checkout and byte-compares the result. It is skipped,
//!    not failed, when that checkout is unavailable, so a standalone public
//!    checkout never depends on it. Only this check can tell that the committed
//!    bundle is older than its private source.
//!
//! Bundle provenance and licensing: `third_party/queryknight-ui/README.md`.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

/// The vendored bundle, relative to this crate.
const BUNDLE: &str = "ui";
/// Pinned SHA-256 manifest for [`BUNDLE`], in `sha256sum` format.
const MANIFEST: &str = "ui.sha256";

fn crate_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn collect_files(root: &Path) -> Vec<PathBuf> {
    fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
        let mut entries: Vec<_> = std::fs::read_dir(dir)
            .expect("read bundle dir")
            .map(|entry| entry.expect("bundle entry").path())
            .collect();
        entries.sort();
        for path in entries {
            if path.is_dir() {
                walk(&path, out);
            } else if path.is_file() {
                out.push(path);
            }
        }
    }
    let mut files = Vec::new();
    walk(root, &mut files);
    files
}

fn relative(root: &Path, files: &[PathBuf]) -> Vec<String> {
    files
        .iter()
        .map(|path| {
            path.strip_prefix(root)
                .expect("bundle file under root")
                .to_string_lossy()
                .replace('\\', "/")
        })
        .collect()
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// Parse a `sha256sum`-style manifest into `path -> digest`.
fn read_manifest(text: &str) -> BTreeMap<String, String> {
    let mut entries = BTreeMap::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (digest, path) = line
            .split_once("  ")
            .unwrap_or_else(|| panic!("manifest line is not `<digest>  <path>`: {line}"));
        assert_eq!(digest.len(), 64, "manifest digest is not SHA-256: {line}");
        assert!(
            entries.insert(path.to_owned(), digest.to_owned()).is_none(),
            "duplicate manifest entry: {path}"
        );
    }
    entries
}

/// Public gate: the committed bundle is exactly the reviewed one.
#[test]
fn bundle_matches_pinned_manifest() {
    let crate_dir = crate_dir();
    let bundle = crate_dir.join(BUNDLE);
    assert!(
        bundle.is_dir(),
        "vendored UI bundle missing: {}",
        bundle.display()
    );

    let manifest_path = crate_dir.join(MANIFEST);
    let text = std::fs::read_to_string(&manifest_path).unwrap_or_else(|error| {
        panic!(
            "cannot read {}: {error}. Regenerate it from the bundle root with \
             `find ui -type f | LC_ALL=C sort | xargs shasum -a 256 > ui.sha256`",
            manifest_path.display()
        )
    });
    let expected = read_manifest(&text);

    let files = collect_files(&bundle);
    let actual_paths = relative(&crate_dir, &files);
    let expected_paths: Vec<String> = expected.keys().cloned().collect();
    assert_eq!(
        actual_paths, expected_paths,
        "vendored UI file set drifted from {MANIFEST}; the bundle must be \
         re-exported and re-pinned together"
    );

    for (rel, path) in expected_paths.iter().zip(&files) {
        let bytes = std::fs::read(path).expect("read bundle file");
        let digest = sha256_hex(&bytes);
        assert_eq!(
            &digest,
            expected.get(rel).expect("manifest entry"),
            "stale or edited vendored asset: {rel}"
        );
    }
}

/// The private checkout that owns the SPA source, when it is available.
fn private_ui_dir() -> Option<PathBuf> {
    // Explicit location wins; otherwise guess the sibling layout that the
    // owner's development environment uses.
    if let Some(dir) = std::env::var_os("QUERYKNIGHT_TS_DIR") {
        let dir = PathBuf::from(dir).join("apps/ui");
        return dir.is_dir().then_some(dir);
    }
    let dir = crate_dir().join("../../../queryknight-ts/apps/ui");
    dir.is_dir().then(|| dir.canonicalize().unwrap_or(dir))
}

/// Owner/developer gate: the committed bundle still matches its private source.
///
/// Skipped when the proprietary checkout or its `node_modules` is unavailable,
/// which is the normal case for a standalone public checkout and for public CI.
#[test]
fn bundle_matches_private_source_build() {
    let Some(ui) = private_ui_dir() else {
        eprintln!(
            "skipping bundle_matches_private_source_build: no queryknight-ts \
             checkout found (set QUERYKNIGHT_TS_DIR to run this owner-only \
             correspondence check). Public integrity is covered by \
             bundle_matches_pinned_manifest."
        );
        return;
    };
    let vite = ui.join("node_modules/.bin/vite");
    if !vite.is_file() {
        eprintln!(
            "skipping bundle_matches_private_source_build: {} has no installed \
             node_modules",
            ui.display()
        );
        return;
    }

    let out = std::env::temp_dir().join(format!("qk-ui-fresh-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&out);
    let build = std::process::Command::new(&vite)
        .arg("build")
        .arg("--outDir")
        .arg(&out)
        .current_dir(&ui)
        .env("NODE_ENV", "production")
        .output()
        .expect("vite build runs");
    assert!(
        build.status.success(),
        "Vue production build failed:\n{}",
        String::from_utf8_lossy(&build.stderr)
    );

    let fresh = collect_files(&out);
    let vendored_root = crate_dir().join(BUNDLE);
    let vendored = collect_files(&vendored_root);
    assert_eq!(
        relative(&out, &fresh),
        relative(&vendored_root, &vendored),
        "dist file set drifted from the vendored bundle"
    );
    for file in &fresh {
        let name = file.strip_prefix(&out).expect("under out");
        let vendored_bytes = std::fs::read(vendored_root.join(name)).expect("vendored bundle file");
        let fresh_bytes = std::fs::read(file).expect("fresh build file");
        assert_eq!(
            vendored_bytes,
            fresh_bytes,
            "stale vendored asset: {}",
            name.display()
        );
    }
    let _ = std::fs::remove_dir_all(&out);
}
