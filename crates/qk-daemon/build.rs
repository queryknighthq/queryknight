//! Compile-time UI asset table: walks `ui/` (a vendored copy of the
//! Vue production `dist/`) and emits `path -> (mime, bytes)` entries
//! backed by `include_bytes!`. No new dependencies; hash-renamed Vite
//! outputs are picked up automatically on rebuild. If `ui/` is absent
//! the build fails loudly — missing frontend assets are a
//! build/packaging error, never repaired at daemon startup.

use std::fmt::Write as _;
use std::path::Path;

fn mime_for(path: &Path) -> &'static str {
    match path.extension().and_then(|ext| ext.to_str()) {
        Some("html") => "text/html; charset=utf-8",
        Some("js") => "text/javascript; charset=utf-8",
        Some("css") => "text/css; charset=utf-8",
        Some("json") => "application/json",
        Some("svg") => "image/svg+xml",
        Some("png") => "image/png",
        Some("jpg" | "jpeg") => "image/jpeg",
        Some("webp") => "image/webp",
        Some("ico") => "image/x-icon",
        Some("woff") => "font/woff",
        Some("woff2") => "font/woff2",
        _ => "application/octet-stream",
    }
}

fn collect(dir: &Path, root: &Path, out: &mut Vec<(String, String)>) {
    let entries = std::fs::read_dir(dir).expect("ui asset directory readable");
    let mut entries: Vec<_> = entries
        .map(|entry| entry.expect("ui entry").path())
        .collect();
    entries.sort();
    for path in entries {
        if path.is_dir() {
            collect(&path, root, out);
        } else if path.is_file() {
            let rel = path
                .strip_prefix(root)
                .expect("ui file under root")
                .to_str()
                .expect("ui paths are UTF-8")
                .to_owned();
            out.push((rel, mime_for(&path).to_owned()));
        }
    }
}

fn main() {
    println!("cargo:rerun-if-changed=ui");
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    let root = manifest.join("ui");
    assert!(root.is_dir(), "ui/ asset directory missing: frontend production bundle must be vendored (see docs/browser-ui.md)");
    let mut files = Vec::new();
    collect(&root, &root, &mut files);
    assert!(
        files.iter().any(|(rel, _)| rel == "index.html"),
        "ui/index.html missing: cannot serve the SPA shell"
    );
    let mut code = String::from(
        "/// Generated UI asset table: (url-relative path, mime, bytes).\nstatic UI_ASSETS: &[(&str, &str, &[u8])] = &[\n",
    );
    for (rel, mime) in &files {
        // `include_bytes!` needs a path relative to the current file
        // (`src/`); the generated file lands in OUT_DIR, so spell the
        // manifest-relative path through the env var at compile time.
        writeln!(
            code,
            "    ({rel:?}, {mime:?}, include_bytes!(concat!(env!(\"CARGO_MANIFEST_DIR\"), \"/ui/{rel}\"))),"
        )
        .expect("codegen");
    }
    code.push_str("];\n");
    let out = Path::new(&std::env::var("OUT_DIR").expect("OUT_DIR")).join("ui_table.rs");
    std::fs::write(out, code).expect("write ui table");
}
