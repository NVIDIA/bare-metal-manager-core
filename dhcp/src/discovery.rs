use std::ffi::CStr;
use std::net::Ipv4Addr;
use std::primitive::u32;

use derive_builder::Builder;
use mac_address::MacAddress;

use crate::machine::Machine;

#[derive(Debug, Builder)]
#[builder(pattern = "owned")]
pub struct Discovery {
    pub(crate) relay_address: Ipv4Addr,
    pub(crate) mac_address: MacAddress,

    #[allow(dead_code)]
    #[builder(setter(into, strip_option), default)]
    pub(crate) client_system: Option<u16>,

    #[builder(setter(into, strip_option), default)]
    pub(crate) vendor_class: Option<String>,

    #[builder(setter(into, strip_option), default)]
    pub(crate) link_select_address: Option<Ipv4Addr>,
}

#[repr(C)]
pub struct DiscoveryBuilderFFI(());

/// Allocate a new struct to fill in the discovery information from the DHCP packet in Kea
///
/// This is an "opaque" pointer to rust data, which must be freed by rust data, and to keep the FFI
/// interface simple there's a series of discovery_set_*() functions that set the data in this
/// struct.
///
#[no_mangle]
pub extern "C" fn discovery_allocate() -> *mut DiscoveryBuilderFFI {
    Box::into_raw(Box::new(DiscoveryBuilder::default())) as _
}

unsafe fn marshal_discovery_ffi<F>(builder: *mut DiscoveryBuilderFFI, f: F)
where
    F: FnOnce(DiscoveryBuilder) -> DiscoveryBuilder,
{
    assert!(!builder.is_null());

    let builder = builder as *mut DiscoveryBuilder;

    let old = builder.read();
    let new = f(old);
    builder.write(new);
}

/// Fill the `client_system` portion of the discovery object
///
/// # Safety
///
/// This function deferences a pointer to a Discovery object which is an opaque pointer
/// consumed in C code.
///
#[no_mangle]
pub unsafe extern "C" fn discovery_set_client_system(
    ctx: *mut DiscoveryBuilderFFI,
    client_system: u16,
) {
    marshal_discovery_ffi(ctx, |builder| builder.client_system(client_system))
}

/// Fill the `vendor_class` portion of the discovery object
///
/// # Safety
///
/// This function deferences a pointer to a Discovery object which is an opaque pointer
/// consumed in C code.
///
#[no_mangle]
pub unsafe extern "C" fn discovery_set_vendor_class(
    ctx: *mut DiscoveryBuilderFFI,
    vendor_class: *const libc::c_char,
) {
    let vendor_class = match CStr::from_ptr(vendor_class).to_str() {
        Ok(string) => string.to_owned(),
        Err(error) => {
            log::error!("Invalid UTF-8 byte string for vendor_class: {}", error);
            return;
        }
    };

    marshal_discovery_ffi(ctx, |builder| builder.vendor_class(vendor_class))
}

/// Fill the `link select` portion of the Discovery object with an IP(v4) address
///
/// # Safety
///
/// This function deferences a pointer to a Discovery object which is an opaque pointer
/// consumed in C code.
///
#[no_mangle]
pub unsafe extern "C" fn discovery_set_link_select(
    ctx: *mut DiscoveryBuilderFFI,
    link_select: u32,
) {
    marshal_discovery_ffi(ctx, |builder| {
        builder.link_select_address(Ipv4Addr::from(link_select.to_be_bytes()))
    });
}

/// Fill the `relay` portion of the Discovery object with an IP(v4) address
///
/// # Safety
///
/// This function deferences a pointer to a Discovery object which is an opaque pointer
/// consumed in C code.
///
#[no_mangle]
pub unsafe extern "C" fn discovery_set_relay(ctx: *mut DiscoveryBuilderFFI, relay: u32) {
    marshal_discovery_ffi(ctx, |builder| {
        builder.relay_address(Ipv4Addr::from(relay.to_be_bytes()))
    });
}

/// Fill the `mac_address` portion of the Discovery object with an IP(v4) address
///
/// # Safety
///
/// This function deferences a pointer to a Discovery object which is an opaque pointer
/// consumed in C code.
///
/// This function constructs a mac address from a *const u8 which is dangerous.  Assertion error if
/// we get passed an array that's not 6 elements
///
#[no_mangle]
pub unsafe extern "C" fn discovery_set_mac_address(
    ctx: *mut DiscoveryBuilderFFI,
    raw_parts: *const u8,
    size: usize,
) {
    assert_eq!(size, 6);

    let mac = match std::slice::from_raw_parts(raw_parts, size).try_into() {
        Ok(mac) => MacAddress::new(mac),
        Err(error) => {
            log::info!(
                "Could not unmarshall u8 slice to 6-bye MAC Address array: {}",
                error
            );
            return;
        }
    };

    marshal_discovery_ffi(ctx, |builder| builder.mac_address(mac));
}

#[no_mangle]
pub extern "C" fn discovery_fetch_machine(ctx: *mut DiscoveryBuilderFFI) -> *mut Machine {
    assert!(!ctx.is_null());
    let ctx = ctx as *mut DiscoveryBuilder;
    let builder = unsafe { ctx.read() };

    let discovery = match builder.build() {
        Ok(discovery) => discovery,
        Err(err) => {
            log::info!("Error compiling the discovery builder object: {}", err);
            return std::ptr::null_mut();
        }
    };

    let r = discovery.relay_address;
    let m = discovery.mac_address;
    let v = match discovery.vendor_class.clone() {
        Some(s) => s,
        None => "No vendor specified in the request".to_string(),
    };

    match Machine::try_from(discovery) {
        Ok(machine) => Box::into_raw(Box::new(machine)),
        Err(e_str) => {
            log::info!(
                "Error getting info back from the machine discovery: {}:{}:{}:{}",
                m,
                r,
                v,
                e_str
            );
            std::ptr::null_mut()
        }
    }
}

/// Free the Discovery object.
///
/// # Safety
///
/// This function deferences a pointer to a Discovery object which is an opaque pointer
/// consumed in C code.
///
/// This does not forget the memory afterwards, so the opaque pointer in the C code is now
/// unusable.
///
#[no_mangle]
pub unsafe extern "C" fn discovery_free(ctx: *mut DiscoveryBuilderFFI) {
    Box::from_raw(ctx as *mut Discovery);
}
