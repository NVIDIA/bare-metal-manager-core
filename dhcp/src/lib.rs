use eui48::{MacAddress, MacAddressFormat};
use std::net::{IpAddr, Ipv4Addr};
use std::ptr;

use rpc::v0 as rpc;

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

#[no_mangle]
pub extern "C" fn discover_set_relay(ctx: *mut MachineDiscovery, relay: u32) -> bool {
    assert!(!ctx.is_null());

    let mut discovery = unsafe { Box::from_raw(ctx) };

    discovery.relay_address = Some(Ipv4Addr::from(relay.to_be_bytes()));

    std::mem::forget(discovery);
    true
}

#[no_mangle]
pub extern "C" fn discover_set_client_macaddress(ctx: *mut MachineDiscovery, raw_parts: *const u8, size: usize) -> bool {
    assert!(!ctx.is_null());

    let mut discovery = unsafe { Box::from_raw(ctx) };
    let mac_address = MacAddress::from_bytes(unsafe { std::slice::from_raw_parts(raw_parts, size) });

    discovery.mac_address = Some(mac_address.unwrap());

    std::mem::forget(discovery);
    true
}

#[no_mangle]
pub extern "C" fn discover_invoke(ctx: *mut MachineDiscovery) -> u32 {
    assert!(!ctx.is_null());
    let mut discovery = unsafe { Box::from_raw(ctx) };

    eprintln!("{:#?}", discovery);
    let ret = discovery.invoke().into();

    std::mem::forget(discovery);
    ret
}

#[no_mangle]
pub extern "C" fn discover_free(ctx: *mut MachineDiscovery) {
    eprintln!("Calling discover_free");

    if ctx.is_null() {
        return;
    }

    unsafe {
        Box::from_raw(ctx);
    }
}

#[no_mangle]
pub extern "C" fn machine_discover(
    discover: *mut MachineDiscovery
) -> *const MachineDiscovery {
    unsafe {
        if discover.is_null() {
            return std::ptr::null();
        }

        let discover: Box<MachineDiscovery> = Box::from_raw(discover);

        eprintln!("{:#?}", discover);

        std::mem::forget(discover);
    }


    std::ptr::null()
}
