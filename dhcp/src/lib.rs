mod discovery;
mod kea;
mod kea_logger;
mod machine;
mod vendor_class;

use libc::c_char;

use once_cell::sync::Lazy;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::RwLock;
use tokio::runtime::{Builder, Runtime};

use std::ffi::CStr;

static CONFIG: Lazy<RwLock<CarbideDhcpContext>> =
    Lazy::new(|| RwLock::new(CarbideDhcpContext::default()));

static LOGGER: kea_logger::KeaLogger = kea_logger::KeaLogger;

#[derive(Debug)]
pub struct CarbideDhcpContext {
    api_endpoint: String,
    provisioning_server_ipv4: Option<Ipv4Addr>,
    #[allow(dead_code)]
    provisioning_server_ipv6: Option<Ipv6Addr>,
}

impl Default for CarbideDhcpContext {
    fn default() -> Self {
        Self {
            api_endpoint: "https://[::1]:1079".to_string(),
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
///
/// None, todo!()
///
#[no_mangle]
pub extern "C" fn carbide_set_config_api(api: *const c_char) {
    let config_api = unsafe { CStr::from_ptr(api) }.to_str().unwrap().to_owned();

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
