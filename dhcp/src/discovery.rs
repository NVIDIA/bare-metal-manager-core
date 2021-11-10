use eui48::MacAddress;
use std::net::Ipv4Addr;
use std::primitive::u32;

use crate::machine::Machine;
use crate::CarbideDhcpContext;

use rpc::v0 as rpc;
use crate::CONFIG;

#[derive(Debug, Default)]
pub struct Discovery {
    pub(crate) relay_address: Option<Ipv4Addr>,
    pub(crate) mac_address: Option<MacAddress>,
    pub(crate) vendor_string: Option<String>,
}

/// Allocate a new struct to fill in the discovery information from the DHCP packet in Kea
///
/// This is an "opaque" pointer to rust data, which must be freed by rust data, and to keep the FFI
/// interface simple there's a series of discovery_set_*() functions that set the data in this
/// struct.
///
#[no_mangle]
pub extern "C" fn discovery_allocate() -> *mut Discovery {
    Box::into_raw(Box::new(Discovery::default()))
}

/// Fill the `relay` portion of the Discovery object with an IP(v4) address
///
/// # Safety
///
/// This function deferences a pointer to a Discovery object which is an opaque pointer
/// consumed in C code.
///
#[no_mangle]
pub unsafe extern "C" fn discovery_set_relay(ctx: *mut Discovery, relay: u32) -> bool {
    assert!(!ctx.is_null());

    let mut discovery = Box::from_raw(ctx);

    discovery.relay_address = Some(Ipv4Addr::from(relay.to_be_bytes()));

    std::mem::forget(discovery);
    true
}

/// Fill the `macaddress` portion of the Discovery object with an IP(v4) address
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
    ctx: *mut Discovery,
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

#[no_mangle]
pub unsafe extern "C" fn discovery_fetch_machine(ctx: *mut Discovery) -> *mut Machine {
    assert!(!ctx.is_null());

    let runtime: &tokio::runtime::Runtime = CarbideDhcpContext::get_tokio_runtime();

    let discovery = Box::from_raw(ctx);

    let machine = runtime.block_on(async move {
        let config = CONFIG.read().unwrap(); 
        let x = config.api_endpoint.clone();

        let mut client = rpc::carbide_client::CarbideClient::connect(x)
            .await
            .unwrap();

        let request = tonic::Request::new(rpc::MachineDiscovery {
            mac_address: discovery.mac_address.unwrap().to_hex_string(),
            relay_address: discovery.relay_address.unwrap().to_string(),
            vendor_string: discovery.vendor_string.unwrap().to_string(),
        });

        let response = client.discover_machine(request).await.unwrap().into_inner();

        Box::new(Machine {
            inner: response,
            discovery_info: discovery,
        })
    });

    Box::into_raw(machine)
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
pub unsafe extern "C" fn discovery_free(ctx: *mut Discovery) {
    if ctx.is_null() {
        return;
    }

    Box::from_raw(ctx);
}
