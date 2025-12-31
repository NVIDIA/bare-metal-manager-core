/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2023 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */

// dhcp package is built for x86_64 and aarch64 architectures
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
fn main() {
    use std::env;

    let kea_include_path =
        env::var("KEA_INCLUDE_PATH").unwrap_or_else(|_| "/usr/include/kea".to_string());

    #[cfg(target_arch = "x86_64")]
    let default_kea_lib_path = "/usr/lib/x86_64-linux-gnu/kea";
    #[cfg(target_arch = "aarch64")]
    let default_kea_lib_path = "/usr/lib/aarch64-linux-gnu/kea";

    let kea_lib_path =
        env::var("KEA_LIB_PATH").unwrap_or_else(|_| default_kea_lib_path.to_string());

    let kea_shim_root = format!("{}/src/kea", env!("CARGO_MANIFEST_DIR"));

    cbindgen::Builder::new()
        .with_crate(env!("CARGO_MANIFEST_DIR"))
        .with_config(cbindgen::Config::from_file("cbindgen.toml").expect("Config file missing"))
        .generate()
        .expect("Unable to generate bindings")
        .write_to_file(format!("{kea_shim_root}/carbide_rust.h"));

    cc::Build::new()
        .cpp(true)
        .file(format!("{kea_shim_root}/logger.cc"))
        .file(format!("{kea_shim_root}/loader.cc"))
        .file(format!("{kea_shim_root}/callouts.cc"))
        .file(format!("{kea_shim_root}/carbide_logger.cc"))
        .include(kea_include_path)
        .pic(true)
        .compile("keashim");

    println!("cargo:rerun-if-changed=src/kea/callouts.cc");
    println!("cargo:rerun-if-changed=src/kea/loader.cc");
    println!("cargo:rerun-if-changed=src/kea/logger.cc");
    println!("cargo:rerun-if-changed=src/kea/carbide_rust.h");
    println!("cargo:rerun-if-changed=src/kea/carbide_logger.cc");
    println!("cargo:rerun-if-changed=src/kea/carbide_logger.h");

    println!("cargo:rustc-link-search={kea_lib_path}");
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

#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
fn main() {}
