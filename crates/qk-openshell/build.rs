use std::path::PathBuf;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let proto_dir = PathBuf::from("proto");
    let proto = proto_dir.join("supervisor_middleware.proto");
    let vendored_protoc = protoc_bin_vendored::protoc_bin_path()?;
    let google_protos = protoc_bin_vendored::include_path()?;
    std::env::set_var("PROTOC", vendored_protoc);
    tonic_prost_build::configure()
        .build_server(true)
        .build_client(true)
        .file_descriptor_set_path(
            PathBuf::from(std::env::var("OUT_DIR")?).join("openshell_descriptor.bin"),
        )
        .compile_protos(
            &[proto, proto_dir.join("extension.proto")],
            &[proto_dir, google_protos],
        )?;

    println!("cargo:rerun-if-changed=proto/supervisor_middleware.proto");
    println!("cargo:rerun-if-changed=proto/extension.proto");
    Ok(())
}
