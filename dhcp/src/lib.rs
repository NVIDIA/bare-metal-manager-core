use std::ffi::CStr;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::RwLock;

use libc::c_char;
use once_cell::sync::Lazy;
use tokio::runtime::{Builder, Runtime};

mod discovery;
mod kea;
mod kea_logger;
mod machine;
mod vendor_class;

static CONFIG: Lazy<RwLock<CarbideDhcpContext>> =
    Lazy::new(|| RwLock::new(CarbideDhcpContext::default()));

static LOGGER: kea_logger::KeaLogger = kea_logger::KeaLogger;

#[derive(Debug)]
pub struct CarbideDhcpContext {
    api_endpoint: String,
    nameservers: String,
    provisioning_server_ipv4: Option<Ipv4Addr>,
    #[allow(dead_code)]
    provisioning_server_ipv6: Option<Ipv6Addr>,
}

impl Default for CarbideDhcpContext {
    fn default() -> Self {
        Self {
            api_endpoint: "https://[::1]:1079".to_string(),
            nameservers: "1.1.1.1".to_string(),
            provisioning_server_ipv4: None,
            provisioning_server_ipv6: None,
        }
    }
}

impl CarbideDhcpContext {
    pub fn get_tokio_runtime() -> &'static Runtime {
        static TOKIO: Lazy<Runtime> =
            Lazy::new(|| Builder::new_current_thread().enable_all().build().unwrap());

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
