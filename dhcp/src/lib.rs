mod discovery;
mod kea;
mod kea_logger;
mod machine;
mod vendor_class;

use libc::c_char;

use once_cell::sync::Lazy;
use std::sync::RwLock;
use tokio::runtime::{Builder, Runtime};

use std::ffi::CStr;

static CONFIG: Lazy<RwLock<CarbideDhcpContext>> =
    Lazy::new(|| RwLock::new(CarbideDhcpContext::default()));

static LOGGER: kea_logger::KeaLogger = kea_logger::KeaLogger;

#[derive(Debug)]
pub struct CarbideDhcpContext {
    pub api_endpoint: String,
}

impl Default for CarbideDhcpContext {
    fn default() -> Self {
        Self {
            api_endpoint: "https://[::1]:1079".to_string(),
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
/// TODO: add things like certificates
///
/// # Safety
///
/// None, todo!()
///
#[no_mangle]
pub unsafe extern "C" fn carbide_set_config_api(api: *const c_char) {
    let config_api = CStr::from_ptr(api).to_str().unwrap().to_owned();

    eprintln!("{:#?}", CStr::from_ptr(api));

    CONFIG.write().unwrap().api_endpoint = config_api;
}
