//! Frontend freshness gate: the vendored `ui/` bundle must be
//! byte-identical to a fresh offline production build of the Vue app.
//! Skipped (not failed) when the Node toolchain or TS checkout is
//! absent; loud when present but stale, so Rust tests can never pass
//! forever against a broken frontend.

use std::path::{Path, PathBuf};

fn ts_ui_dir() -> Option<PathBuf> {
    // Explicit checkout location wins; otherwise guess the sibling
    // layout (integration tests run with the crate directory as CWD).
    if let Some(dir) = std::env::var_os("QUERYKNIGHT_TS_DIR") {
        let dir = PathBuf::from(dir).join("apps/ui");
        return dir.is_dir().then_some(dir);
    }
    let dir = Path::new("../../../queryknight-ts/apps/ui");
    dir.is_dir().then(|| dir.to_owned())
}

fn collect(dir: &Path, out: &mut Vec<PathBuf>) {
    let mut entries: Vec<_> = std::fs::read_dir(dir)
        .expect("read dir")
        .map(|entry| entry.expect("entry").path())
        .collect();
    entries.sort();
    for path in entries {
        if path.is_dir() {
            collect(&path, out);
        } else if path.is_file() {
            out.push(path);
        }
    }
}

#[test]
fn vendored_bundle_matches_fresh_production_build() {
    let Some(ui) = ts_ui_dir() else {
        eprintln!("skipping: TS checkout absent");
        return;
    };
    let vite = ui.join("node_modules/.bin/vite");
    if !vite.is_file() {
        eprintln!("skipping: frontend node_modules absent (offline)");
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
    // Byte-compare the full file set (names + contents).
    let mut fresh = Vec::new();
    collect(&out, &mut fresh);
    let vendored_root = Path::new("ui");
    let mut vendored = Vec::new();
    collect(vendored_root, &mut vendored);
    let rel = |root: &Path, files: &[PathBuf]| -> Vec<String> {
        files
            .iter()
            .map(|path| {
                path.strip_prefix(root)
                    .expect("under root")
                    .to_string_lossy()
                    .into_owned()
            })
            .collect()
    };
    assert_eq!(
        rel(&out, &fresh),
        rel(vendored_root, &vendored),
        "dist file set drifted"
    );
    for file in &fresh {
        let name = file.strip_prefix(&out).expect("under out");
        let vendored_bytes = std::fs::read(vendored_root.join(name)).expect("vendored file");
        let fresh_bytes = std::fs::read(file).expect("fresh file");
        assert_eq!(
            vendored_bytes,
            fresh_bytes,
            "stale vendored asset: {}",
            name.display()
        );
    }
    let _ = std::fs::remove_dir_all(&out);
}
