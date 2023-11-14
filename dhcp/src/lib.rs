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
use std::ffi::CStr;
use std::net::Ipv4Addr;
use std::sync::RwLock;
use std::thread;

use libc::c_char;
use once_cell::sync::Lazy;
use tokio::runtime::{Builder, Runtime};

mod cache;
mod discovery;
mod kea;
mod kea_logger;
mod machine;
mod vendor_class;

// Should be #[cfg(test)] but tests/integration_test.rs also uses it
mod metrics;
pub mod mock_api_server;
mod tls;

static CONFIG: Lazy<RwLock<CarbideDhcpContext>> =
    Lazy::new(|| RwLock::new(CarbideDhcpContext::default()));

static LOGGER: kea_logger::KeaLogger = kea_logger::KeaLogger;

#[derive(Debug)]
pub struct CarbideDhcpContext {
    api_endpoint: String,
    otlp_endpoint: Option<String>,
    nameservers: String,
    ntpserver: String,
    provisioning_server_ipv4: Option<Ipv4Addr>,
    forge_root_ca_path: String,
    forge_client_cert_path: String,
    forge_client_key_path: String,
}

impl Default for CarbideDhcpContext {
    fn default() -> Self {
        Self {
            api_endpoint: "https://[::1]:1079".to_string(),
            otlp_endpoint: None,
            nameservers: "1.1.1.1".to_string(),
            forge_root_ca_path: std::env::var("FORGE_ROOT_CAFILE_PATH")
                .unwrap_or_else(|_| rpc::forge_tls_client::DEFAULT_ROOT_CA.to_string()),
            forge_client_cert_path: std::env::var("FORGE_CLIENT_CERT_PATH")
                .unwrap_or_else(|_| rpc::forge_tls_client::DEFAULT_CLIENT_CERT.to_string()),
            forge_client_key_path: std::env::var("FORGE_CLIENT_KEY_PATH")
                .unwrap_or_else(|_| rpc::forge_tls_client::DEFAULT_CLIENT_KEY.to_string()),
            ntpserver: "172.20.0.24".to_string(), // local ntp server
            provisioning_server_ipv4: None,
        }
    }
}

impl CarbideDhcpContext {
    pub fn get_tokio_runtime() -> &'static Runtime {
        static TOKIO: Lazy<Runtime> = Lazy::new(|| {
            let runtime = Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("unable to build runtime?");

            thread::spawn(metrics::sync_metrics_loop);

            runtime
        });

        &TOKIO
    }
}

/// Take the config parameter from Kea and configure it as our API endpoint
///
/// # Safety
/// Function is unsafe as it dereferences a raw pointer given to it.  Caller is responsible
/// to validate that the pointer passed to it meets the necessary conditions to be dereferenced.
///
#[no_mangle]
pub unsafe extern "C" fn carbide_set_config_api(api: *const c_char) {
    let config_api = CStr::from_ptr(api).to_str().unwrap().to_owned();

    CONFIG.write().unwrap().api_endpoint = config_api;
}

/// Take the config parameter from Kea and configure it as our OTLP endpoint
///
/// # Safety
/// Function is unsafe as it dereferences a raw pointer given to it.  Caller is responsible
/// to validate that the pointer passed to it meets the necessary conditions to be dereferenced.
///
#[no_mangle]
pub unsafe extern "C" fn carbide_set_config_otlp(otlp: *const c_char) {
    let config_otlp = CStr::from_ptr(otlp).to_str().unwrap().to_owned();

    CONFIG.write().unwrap().otlp_endpoint = Some(config_otlp);
}

/// Take the next-server IP which will be configured as the endpoint for the iPXE client (and DNS
/// for now)
///
/// # Safety
///
/// None, todo!()
///
#[no_mangle]
pub extern "C" fn carbide_set_config_next_server_ipv4(next_server: u32) {
    CONFIG.write().unwrap().provisioning_server_ipv4 =
        Some(Ipv4Addr::from(next_server.to_be_bytes()));
}

/// Take the name servers for configuring nameservers in the dhcp responses
///
/// # Safety
/// Function is unsafe as it dereferences a raw pointer given to it.  Caller is responsible
/// to validate that the pointer passed to it meets the necessary conditions to be dereferenced.
///
#[no_mangle]
pub unsafe extern "C" fn carbide_set_config_name_servers(nameservers: *const c_char) {
    let nameserver_str = CStr::from_ptr(nameservers).to_str().unwrap().to_owned();

    CONFIG.write().unwrap().nameservers = nameserver_str;
}

/// Take the NTP servers for configuring NTP in the dhcp responses
///
/// # Safety
/// Function is unsafe as it dereferences a raw pointer given to it.  Caller is responsible
/// to validate that the pointer passed to it meets the necessary conditions to be dereferenced.
///
#[no_mangle]
pub unsafe extern "C" fn carbide_set_config_ntp(ntpserver: *const c_char) {
    let ntp_str = CStr::from_ptr(ntpserver).to_str().unwrap().to_owned();

    CONFIG.write().unwrap().ntpserver = ntp_str;
}
