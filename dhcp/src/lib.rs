mod kea {
    #[repr(C)]
    pub struct OpaquePointer { _private: [u8; 0] }

    extern "C" {
        pub fn shim_version() -> libc::c_int;
        pub fn shim_load(_: *mut OpaquePointer) -> libc::c_int;
        pub fn shim_unload() -> libc::c_int;
        pub fn shim_multi_threaded_compatible() -> libc::c_int;
    }
}

#[no_mangle]
pub unsafe extern "C" fn version() -> libc::c_int {
    kea::shim_version()
}

#[no_mangle]
pub unsafe extern "C" fn load(a: *mut kea::OpaquePointer) -> libc::c_int {
    kea::shim_load(a)
}

#[no_mangle]
pub unsafe extern "C" fn unload() -> libc::c_int {
    kea::shim_unload()
}

#[no_mangle]
pub unsafe extern "C" fn multi_threaded_compatible() -> libc::c_int {
    kea::shim_multi_threaded_compatible()
}
