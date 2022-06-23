use std::path::PathBuf;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let out_dir = PathBuf::from(std::env!("CARGO_MANIFEST_DIR"))
        .join("src")
        .join("generated");

    let reflection = PathBuf::from(&out_dir).join("forge.v0.bin");

    tonic_build::configure()
        .file_descriptor_set_path(&reflection)
        .include_file("mod.rs")
        .type_attribute("forge.v0.MachineState", "#[derive(serde::Serialize)]")
        .type_attribute("forge.v0.MachineInterface", "#[derive(serde::Serialize)]")
        .type_attribute("forge.v0.UUID", "#[derive(serde::Serialize)]")
        .build_server(true)
        .build_client(true)
        .out_dir(format!("{}", out_dir.display()))
        .compile(
            &["proto/forge.proto", "proto/machine_discovery.proto"],
            &["proto"],
        )
        .unwrap();

    Ok(())
}
