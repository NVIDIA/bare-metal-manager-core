use mac_address::MacAddress;
use std::net::Ipv4Addr;
use std::primitive::u32;

use crate::machine::Machine;
use crate::CarbideDhcpContext;

use crate::CONFIG;
use derive_builder::Builder;
use log::*;
use rpc::v0 as rpc;

#[derive(Debug, Builder)]
#[builder(pattern = "owned")]
pub struct Discovery {
    pub(crate) relay_address: Ipv4Addr,
    pub(crate) mac_address: MacAddress,
    //pub(crate) vendor_string: String,
    pub(crate) client_system: u16,
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
    ctx: *mut DiscoveryBuilderFFI,
    raw_parts: *const u8,
    size: usize,
) {
    assert!(size == 6);

    let mac = match std::slice::from_raw_parts(raw_parts, size).try_into() {
        Ok(mac) => MacAddress::new(mac),
        Err(error) => {
            info!(
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
            info!("Error compiling the discovery builder object: {}", err);
            return std::ptr::null_mut();
        }
    };

    // Spawn a tokio runtime and schedule the API connection and machine retrieval to an async
    // thread.  This is required beause tonic is async but this code generally is not.
    //
    // TODO: how to reason about FFI code with async.
    //
    let runtime: &tokio::runtime::Runtime = CarbideDhcpContext::get_tokio_runtime();
    let machine = runtime.block_on(async move {
        let config = CONFIG.read().unwrap();
        let url = config.api_endpoint.clone();

        match rpc::carbide_client::CarbideClient::connect(url).await {
            Ok(mut client) => {
                let request = tonic::Request::new(rpc::MachineDiscovery {
                    mac_address: discovery.mac_address.to_string(),
                    relay_address: discovery.relay_address.to_string(),
                    //vendor_string: discovery.vendor_string.unwrap().to_string(),
                });

                match client.discover_machine(request).await {
                    Ok(response) => Some(Machine {
                        inner: response.into_inner(),
                        discovery_info: discovery,
                    }),
                    Err(error) => {
                        error!("unable to discover machine via Carbide: {:?}", error);
                        None
                    }
                }
            }
            Err(e) => {
                error!("unable to connect to Carbide API: {:?}", e);
                None
            }
        }
    });

    match machine {
        Some(machine) => Box::into_raw(Box::new(machine)),
        None => std::ptr::null_mut(),
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
