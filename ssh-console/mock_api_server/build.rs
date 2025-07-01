fn main() -> Result<(), Box<dyn std::error::Error>> {
    forge_version::build();
    tonic_build::configure()
        .build_server(true)
        .build_client(false) // we're using ForgeApiClient from rpc crate
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
