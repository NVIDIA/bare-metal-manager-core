use std::env;
use std::path::PathBuf;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let reflection = PathBuf::from(env::var("OUT_DIR").unwrap()).join("carbide.v0.bin");

    tonic_build::configure()
        .file_descriptor_set_path(&reflection)
        .type_attribute("carbide.v0.MachineState", "#[derive(serde::Serialize)]")
        .type_attribute("carbide.v0.MachineInterface", "#[derive(serde::Serialize)]")
        .type_attribute("carbide.v0.UUID", "#[derive(serde::Serialize)]")
        .build_server(true)
        .build_client(true)
        .compile(&["proto/carbide.proto"], &["proto/"])?;
    Ok(())
}
