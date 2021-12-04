use log::info;
use log::LevelFilter;

#[repr(C)]
pub struct OpaquePointer {
    _private: [u8; 0],
}

extern "C" {
    pub fn shim_version() -> libc::c_int;
    pub fn shim_load(_: *mut OpaquePointer) -> libc::c_int;
    pub fn shim_unload() -> libc::c_int;
    pub fn shim_multi_threaded_compatible() -> libc::c_int;
}

#[no_mangle]
pub unsafe extern "C" fn version() -> libc::c_int {
    shim_version()
}

#[no_mangle]
pub unsafe extern "C" fn load(a: *mut OpaquePointer) -> libc::c_int {
    log::set_logger(&crate::LOGGER)
        .map(|()| log::set_max_level(LevelFilter::Trace))
        .expect("Error initializing logger, failing.");

    info!("Initialized Logger");

    shim_load(a)
}

#[no_mangle]
pub unsafe extern "C" fn unload() -> libc::c_int {
    shim_unload()
}

#[no_mangle]
pub unsafe extern "C" fn multi_threaded_compatible() -> libc::c_int {
    shim_multi_threaded_compatible()
}
