use log::LevelFilter;

extern "C" {
    pub fn shim_version() -> libc::c_int;
    pub fn shim_load(_: *mut libc::c_void) -> libc::c_int;
    pub fn shim_unload() -> libc::c_int;
    pub fn shim_multi_threaded_compatible() -> libc::c_int;
}

#[no_mangle]
pub unsafe extern "C" fn version() -> libc::c_int {
    shim_version()
}

#[no_mangle]
pub unsafe extern "C" fn load(a: *mut libc::c_void) -> libc::c_int {
    match log::set_logger(&crate::LOGGER).map(|()| log::set_max_level(LevelFilter::Trace)) {
        Ok(_) => log::info!("Initialized Logger"),
        Err(err) => {
            eprintln!("Unable to initialize logger: {}", err);
            return 1;
        }
    };

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
