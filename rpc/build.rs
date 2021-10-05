use std::path::PathBuf;
use std::env;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let reflection = PathBuf::from(env::var("OUT_DIR").unwrap()).join("carbide.v0.bin");

    tonic_build::configure()
        .file_descriptor_set_path(&reflection)
        .build_server(true)
        .build_client(true)
        .compile(&["proto/carbide.proto"], &["proto/"])?;
    Ok(())
}
