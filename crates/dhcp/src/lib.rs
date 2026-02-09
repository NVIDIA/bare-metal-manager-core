/*
 * SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
use std::ffi::CStr;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::atomic::AtomicI64;
use std::sync::{Arc, RwLock};
use std::thread;

use forge_tls::default as tls_default;
use libc::c_char;
use metrics_endpoint::HealthController;
use once_cell::sync::Lazy;
use opentelemetry::metrics::Counter;
use rpc::forge_tls_client::ForgeClientConfig;
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
    nameservers: String,
    mqtt_server: Option<String>,
    ntpservers: String,
    provisioning_server_ipv4: Option<Ipv4Addr>,
    forge_root_ca_path: String,
    forge_client_cert_path: String,
    forge_client_key_path: String,
    metrics_endpoint: Option<SocketAddr>,
    metrics: Option<CarbideDhcpMetrics>,
    health_controller: Option<HealthController>,
    startup_time: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Clone)]
pub struct CarbideDhcpMetrics {
    total_requests_counter: Counter<u64>,
    dropped_requests_counter: Counter<u64>,
    forge_client_config: ForgeClientConfig,
    certificate_expiration_value: Arc<AtomicI64>,
}

impl Default for CarbideDhcpContext {
    fn default() -> Self {
        Self {
            api_endpoint: "https://[::1]:1079".to_string(),
            nameservers: "1.1.1.1".to_string(),
            forge_root_ca_path: std::env::var("FORGE_ROOT_CAFILE_PATH")
                .unwrap_or_else(|_| tls_default::ROOT_CA.to_string()),
            forge_client_cert_path: std::env::var("FORGE_CLIENT_CERT_PATH")
                .unwrap_or_else(|_| tls_default::CLIENT_CERT.to_string()),
            forge_client_key_path: std::env::var("FORGE_CLIENT_KEY_PATH")
                .unwrap_or_else(|_| tls_default::CLIENT_KEY.to_string()),
            ntpservers: "172.20.0.24,172.20.0.26,172.20.0.27".to_string(), // local ntp servers
            mqtt_server: None,
            provisioning_server_ipv4: None,
            metrics_endpoint: None,
            metrics: None,
            health_controller: None,
            startup_time: chrono::Utc::now(),
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

            thread::spawn(metrics::metrics_server);

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
#[unsafe(no_mangle)]
pub unsafe extern "C" fn carbide_set_config_api(api: *const c_char) {
    unsafe {
        let config_api = CStr::from_ptr(api).to_str().unwrap().to_owned();
        CONFIG.write().unwrap().api_endpoint = config_api;
    }
}

/// Take the next-server IP which will be configured as the endpoint for the iPXE client (and DNS
/// for now)
///
/// # Safety
///
/// None, todo!()
///
#[unsafe(no_mangle)]
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
#[unsafe(no_mangle)]
pub unsafe extern "C" fn carbide_set_config_name_servers(nameservers: *const c_char) {
    unsafe {
        let nameserver_str = CStr::from_ptr(nameservers).to_str().unwrap().to_owned();
        CONFIG.write().unwrap().nameservers = nameserver_str;
    }
}

/// Take the MQTT server for configuring mqtt_server in DHCP option 224.
///
/// # Safety
/// Function is unsafe as it dereferences a raw pointer given to it.  Caller is responsible
/// to validate that the pointer passed to it meets the necessary conditions to be dereferenced.
///
#[unsafe(no_mangle)]
pub unsafe extern "C" fn carbide_set_config_mqtt_server(mqttserver: *const c_char) {
    unsafe {
        let mqttserver_str = CStr::from_ptr(mqttserver).to_str().unwrap().to_owned();
        CONFIG.write().unwrap().mqtt_server = Some(mqttserver_str);
    }
}

/// Take the NTP servers for configuring NTP in the dhcp responses
///
/// # Safety
/// Function is unsafe as it dereferences a raw pointer given to it.  Caller is responsible
/// to validate that the pointer passed to it meets the necessary conditions to be dereferenced.
///
#[unsafe(no_mangle)]
pub unsafe extern "C" fn carbide_set_config_ntp(ntpservers: *const c_char) {
    unsafe {
        let ntp_str = CStr::from_ptr(ntpservers).to_str().unwrap().to_owned();
        CONFIG.write().unwrap().ntpservers = ntp_str;
    }
}

/// Take the config parameter from Kea and configure it as our metrics endpoint
///
/// # Safety
/// Function is unsafe as it dereferences a raw pointer given to it.  Caller is responsible
/// to validate that the pointer passed to it meets the necessary conditions to be dereferenced.
///
#[unsafe(no_mangle)]
pub unsafe extern "C" fn carbide_set_config_metrics_endpoint(endpoint: *const c_char) {
    unsafe {
        let config_metrics_endpoint = CStr::from_ptr(endpoint).to_str().unwrap().to_owned();
        match config_metrics_endpoint.parse::<SocketAddr>() {
            Ok(metrics_endpoint) => {
                log::info!("metrics endpoint: {config_metrics_endpoint}");
                CONFIG.write().unwrap().metrics_endpoint = Some(metrics_endpoint);
                // this will initiate metrics server
                CarbideDhcpContext::get_tokio_runtime();
            }
            Err(err) => {
                log::error!("failed to parse metrics endpoint {config_metrics_endpoint} : {err}");
            }
        }
    }
}

/// Increments counter for total number of requests
///
/// # Safety
///
/// None
#[unsafe(no_mangle)]
pub unsafe extern "C" fn carbide_increment_total_requests() {
    metrics::increment_total_requests();
}

/// Increments counter for number of dropped requests
///
/// # Safety
///
/// None
#[unsafe(no_mangle)]
pub unsafe extern "C" fn carbide_increment_dropped_requests(reason: *const c_char) {
    unsafe {
        let reason_value = CStr::from_ptr(reason).to_str().unwrap().to_owned();
        metrics::increment_dropped_requests(reason_value);
    }
}
