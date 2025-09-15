fn main() -> Result<(), Box<dyn std::error::Error>> {
    forge_version::build();
    tonic_prost_build::configure()
        .build_server(true)
        .build_client(false) // we're using ForgeApiClient from rpc crate
        .extern_path(".common.MachineId", "::forge_uuid::machine::MachineId")
        .protoc_arg("--experimental_allow_proto3_optional")
        .out_dir("src/generated")
        .compile_protos(
            &[
                "proto/common.proto",
                "proto/forge.proto",
                "proto/machine_discovery.proto",
                "proto/site_explorer.proto",
            ],
            &["proto"],
        )?;
    Ok(())
}
