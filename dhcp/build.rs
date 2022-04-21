use std::env;
use std::process::Command;

fn main() {
    let kea_include_path =
        env::var("KEA_INCLUDE_PATH").unwrap_or_else(|_| "/usr/include/kea".to_string());
    let kea_bin_path = env::var("KEA_BIN_PATH").unwrap_or_else(|_| "/usr/bin".to_string());
    let kea_lib_path =
        env::var("KEA_LIB_PATH").unwrap_or_else(|_| "/usr/lib/x86_64-linux-gnu/kea".to_string());

    let kea_shim_root = format!("{}/src/kea", env!("CARGO_MANIFEST_DIR"));

    Command::new(format!("{}/kea-msg-compiler", kea_bin_path))
        .args(&["-d", &kea_shim_root[..]])
        .arg(format!("{}/carbide_logger.mes", kea_shim_root))
        .status()
        .expect("Cannot find `kea-msg-compiler` bianry.  Check your package installation for the `-dev` package, or, if compiling it yourself use `./configure --enable-generate-messages` to produce the binary");

    cbindgen::Builder::new()
        .with_crate(env!("CARGO_MANIFEST_DIR"))
        .with_config(cbindgen::Config::from_file("cbindgen.toml").expect("Config file missing"))
        .generate()
        .expect("Unable to generate bindings")
        .write_to_file(format!("{}/carbide_rust.h", kea_shim_root));

    cc::Build::new()
        .cpp(true)
        .file(format!("{}/logger.cc", kea_shim_root))
        .file(format!("{}/loader.cc", kea_shim_root))
        .file(format!("{}/callouts.cc", kea_shim_root))
        .file(format!("{}/carbide_logger.cc", kea_shim_root))
        .include(kea_include_path)
        .shared_flag(false)
        .static_flag(false)
        .pic(true)
        .compile("keashim");

    println!("cargo:rerun-if-changed=src/kea/callouts.cc");
    println!("cargo:rerun-if-changed=src/kea/loader.cc");
    println!("cargo:rerun-if-changed=src/kea/logger.cc");
    println!("cargo:rerun-if-changed=src/kea/carbide_rust.h");
    println!("cargo:rerun-if-changed=src/kea/carbide_logger.cc");
    println!("cargo:rerun-if-changed=src/kea/carbide_logger.h");

    println!("cargo:rustc-link-search={}", kea_lib_path);
    println!("cargo:rustc-link-lib=keashim");
    println!("cargo:rustc-link-lib=stdc++");
    println!("cargo:rustc-link-lib=kea-asiolink");
    println!("cargo:rustc-link-lib=kea-dhcpsrv");
    println!("cargo:rustc-link-lib=kea-dhcp++");
    println!("cargo:rustc-link-lib=kea-hooks");
    println!("cargo:rustc-link-lib=kea-log");
    println!("cargo:rustc-link-lib=kea-util");
    println!("cargo:rustc-link-lib=kea-exceptions");
}
