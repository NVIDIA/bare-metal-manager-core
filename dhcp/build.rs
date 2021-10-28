use std::env;
use std::process::Command;

fn main() {
    let kea_include_path =
        env::var("KEA_INCLUDE_PATH").unwrap_or("/opt/kea-2.0.0/include/kea".to_string());
    let kea_bin_path = env::var("KEA_BIN_PATH").unwrap_or("/opt/kea-2.0.0/bin".to_string());

    let kea_shim_root = format!("{}/src/kea", env!("CARGO_MANIFEST_DIR"));

    Command::new(format!("{}/kea-msg-compiler", kea_bin_path))
        .args(&["-d", &kea_shim_root[..]])
        .arg(format!("{}/carbide_logger.mes", kea_shim_root))
        .status()
        .unwrap();

    cbindgen::Builder::new()
        .with_crate(env!("CARGO_MANIFEST_DIR"))
        .generate()
        .expect("Unable to generate bindings")
        .write_to_file(format!("{}/carbide_rust.h", kea_shim_root));

    cc::Build::new()
        .cpp(true)
        .file(format!("{}/shim.cc", kea_shim_root))
        .file(format!("{}/carbide_logger.cc", kea_shim_root))
        .include(kea_include_path)
        .shared_flag(false)
        .static_flag(false)
        .pic(true)
        .compile("keashim");

    println!("cargo:rerun-if-changed=src/kea/shim.cc");
    println!("cargo:rustc-link-lib=keashim");
}
