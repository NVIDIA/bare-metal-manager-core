mod discovery;
mod kea;
mod machine;

use libc::c_char;

use once_cell::sync::Lazy;
use tokio::runtime::{Builder, Runtime};

use std::ffi::CStr;

#[derive(Default)]
pub struct CarbideDhcpContext {
    pub api_endpoint: Option<String>,
}

impl CarbideDhcpContext {
    pub fn get_tokio_runtime() -> &'static Runtime {
        static TOKIO: Lazy<Runtime> =
            Lazy::new(|| Builder::new_current_thread().enable_all().build().unwrap());

        &TOKIO
    }

    pub fn get() -> &'static Self {
        static CONTEXT: Lazy<CarbideDhcpContext> = Lazy::new(|| CarbideDhcpContext::default());
        &CONTEXT
    }

    pub fn api_url(&self) -> &str {
        &self
            .api_endpoint
            .unwrap_or("https://[::1]:1079".to_string())
    }
}

#[no_mangle]
pub unsafe extern "C" fn carbide_set_config_api(api: *const c_char) {
    CarbideDhcpContext::get().api_endpoint = Some(CStr::from_ptr(api).to_str().unwrap().to_owned());
}
