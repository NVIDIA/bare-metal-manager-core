use eui48::MacAddress;
use std::net::Ipv4Addr;

/// cbindgen:ignore
mod kea {
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
}

#[derive(Debug, Default)]
pub struct MachineDiscovery {
    relay_address: Option<Ipv4Addr>,
    mac_address: Option<MacAddress>,
}

impl MachineDiscovery {
    fn invoke(&mut self) -> Ipv4Addr {
        Ipv4Addr::LOCALHOST
    }
}

#[no_mangle]
pub extern "C" fn discover_allocate() -> *mut MachineDiscovery {
    Box::into_raw(Box::new(MachineDiscovery::default()))
}

/// Fill the `relay` portion of the MachineDiscovery object with an IP(v4) address
///
/// # Safety
///
/// This function deferences a pointer to a MachineDiscovery object which is an opaque pointer
/// consumed in C code.
///
#[no_mangle]
pub unsafe extern "C" fn discover_set_relay(ctx: *mut MachineDiscovery, relay: u32) -> bool {
    assert!(!ctx.is_null());

    let mut discovery = Box::from_raw(ctx);

    discovery.relay_address = Some(Ipv4Addr::from(relay.to_be_bytes()));

    std::mem::forget(discovery);
    true
}

/// Fill the `macaddress` portion of the MachineDiscovery object with an IP(v4) address
///
/// # Safety
///
/// This function deferences a pointer to a MachineDiscovery object which is an opaque pointer
/// consumed in C code.
///
/// This function constructs a mac address from a *const u8 which is dangerous.  Assertion error if
/// we get passed an array that's not 6 elements
///
#[no_mangle]
pub unsafe extern "C" fn discover_set_client_macaddress(
    ctx: *mut MachineDiscovery,
    raw_parts: *const u8,
    size: usize,
) -> bool {
    assert!(!ctx.is_null());
    assert!(size == 6);

    let mut discovery = Box::from_raw(ctx);
    let mac_address = MacAddress::from_bytes(std::slice::from_raw_parts(raw_parts, size));

    discovery.mac_address = Some(mac_address.unwrap());

    std::mem::forget(discovery);
    true
}

/// Invoke the discovery processs
///
/// # Safety
///
/// This function deferences a pointer to a MachineDiscovery object which is an opaque pointer
/// consumed in C code.
///
/// TODO: make sure required fields got set by `discover_set_*`
///
#[no_mangle]
pub unsafe extern "C" fn discover_invoke(ctx: *mut MachineDiscovery) -> u32 {
    assert!(!ctx.is_null());
    let mut discovery = Box::from_raw(ctx);

    eprintln!("{:#?}", discovery);
    let ret = discovery.invoke().into();

    std::mem::forget(discovery);
    ret
}

/// Free the MachineDiscovery object.
///
/// # Safety
///
/// This function deferences a pointer to a MachineDiscovery object which is an opaque pointer
/// consumed in C code.
///
/// This does not forget the memory afterwards, so the opaque pointer in the C code is now
/// unusable.
///
#[no_mangle]
pub unsafe extern "C" fn discover_free(ctx: *mut MachineDiscovery) {
    eprintln!("Calling discover_free");

    if ctx.is_null() {
        return;
    }

    Box::from_raw(ctx);
}
