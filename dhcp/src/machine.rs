use crate::discovery::Discovery;
use crate::vendor_class::MachineArchitecture;
use crate::vendor_class::MachineClientClass;
use crate::vendor_class::VendorClass;
use crate::CarbideDhcpContext;
use crate::CONFIG;
use ipnetwork::IpNetwork;
#[allow(unused_imports)]
use log::{debug, error, info, trace, warn, LevelFilter};
use rpc::v0 as rpc;
use std::ffi::CString;
use std::net::Ipv4Addr;
use std::primitive::u32;
use std::ptr;

/// Machine: a machine that's currently trying to boot something
///
/// This just stores the protobuf DHCP record and the discovery info the client used so we can add
/// additional constraints (options) to and from the client.
///
#[derive(Debug)]
pub struct Machine {
    pub inner: rpc::DhcpRecord,
    pub discovery_info: Discovery,
    pub vendor_class: Option<VendorClass>,
}

pub enum MachineTranslateError {
    Failure,
}

impl TryFrom<Discovery> for Machine {
    type Error = MachineTranslateError;

    fn try_from(discovery: Discovery) -> Result<Self, Self::Error> {
        // First, see if we can parse the vendor class
        let vendor_class = match discovery.vendor_class {
            Some(ref vendor_class) => Some(
                vendor_class
                    .parse::<VendorClass>()
                    .map_err(|_| MachineTranslateError::Failure)?,
            ),
            None => None,
        };

        // Option<X>
        //   if none then none
        //   if some then parse if err fail

        let url = CONFIG
            .read()
            .unwrap() // TODO(ajf): don't unwrap
            .api_endpoint
            .clone();

        // Spawn a tokio runtime and schedule the API connection and machine retrieval to an async
        // thread.  This is required beause tonic is async but this code generally is not.
        //
        // TODO(ajf): how to reason about FFI code with async.
        //
        let runtime: &tokio::runtime::Runtime = CarbideDhcpContext::get_tokio_runtime();

        runtime.block_on(async move {
            match rpc::metal_client::MetalClient::connect(url).await {
                Ok(mut client) => {
                    let request = tonic::Request::new(rpc::DhcpDiscovery {
                        mac_address: discovery.mac_address.to_string(),
                        relay_address: discovery.relay_address.to_string(),
                        //vendor_string: discovery.vendor_string.unwrap().to_string(),
                    });

                    client
                        .discover_dhcp(request)
                        .await
                        .map(|response| Machine {
                            inner: response.into_inner(),
                            discovery_info: discovery,
                            vendor_class,
                        })
                        .map_err(|error| {
                            error!("unable to discover machine via Carbide: {:?}", error);
                            MachineTranslateError::Failure
                        })
                }
                Err(err) => {
                    error!("unable to connect to Carbide API: {:?}", err);
                    Err(MachineTranslateError::Failure)
                }
            }
        })
    }
}

/// Get the router address
///
/// # Safety
///
/// This function deferences a pointer to a Machine object which is an opaque pointer
/// consumed in C code.
///
#[no_mangle]
pub extern "C" fn machine_get_interface_router(ctx: *mut Machine) -> u32 {
    assert!(!ctx.is_null());
    let machine = unsafe { Box::from_raw(ctx) };

    // todo(ajf): I guess??
    let default_router = "0.0.0.0".to_string();

    let maybe_gateway = machine
        .inner
        .gateway
        .as_ref()
        .unwrap_or_else(|| {
            warn!(
                "No gateway provided for machine interface: {:?}",
                &machine.inner.machine_interface_id
            );
            &default_router
        })
        .parse::<IpNetwork>();

    std::mem::forget(machine);

    match maybe_gateway {
        Ok(gateway) => match gateway {
            IpNetwork::V4(gateway) => return u32::from_be_bytes(gateway.ip().octets()),
            IpNetwork::V6(gateway) => {
                error!(
                    "Gateway ({}) is an IPv6 address, which is not supported.",
                    gateway
                );
            }
        },
        Err(error) => {
            error!(
                "Gateway value in deserialized protobuf is not an IP Network: {0}",
                error
            );
        }
    };

    0
}

/// Invoke the discovery processs
///
/// # Safety
/// This function deferences a pointer to a Machine object which is an opaque pointer
/// consumed in C code.
///
#[no_mangle]
pub extern "C" fn machine_get_interface_address(ctx: *mut Machine) -> u32 {
    assert!(!ctx.is_null());
    let machine = unsafe { Box::from_raw(ctx) };

    let maybe_address = machine.inner.address.parse::<IpNetwork>();

    std::mem::forget(machine);

    match maybe_address {
        Ok(address) => match address {
            IpNetwork::V4(address) => return u32::from_be_bytes(address.ip().octets()),
            IpNetwork::V6(address) => {
                error!(
                    "Address ({}) is an IPv6 address, which is not supported.",
                    address
                );
            }
        },
        Err(error) => {
            error!(
                "Address value in deserialized protobuf is not an IP Network: {0}",
                error
            );
        }
    };

    0
}

/// Get the machine fqdn
///
/// # Safety
/// This function checks for null pointer and unboxes into a machine object
///
#[no_mangle]
pub extern "C" fn machine_get_interface_hostname(ctx: *mut Machine) -> *mut libc::c_char {
    assert!(!ctx.is_null());
    let machine = unsafe { Box::from_raw(ctx) };

    let fqdn = CString::new(&machine.inner.fqdn[..]).unwrap();

    std::mem::forget(machine);

    fqdn.into_raw()
}

/// Get the machine fqdn
///
/// # Safety
/// This function checks for null pointer and unboxes into a machine object
///
#[no_mangle]
pub extern "C" fn machine_get_filename(ctx: *mut Machine) -> *const libc::c_char {
    assert!(!ctx.is_null());
    let machine = unsafe { Box::from_raw(ctx) };

    let url = if let Some(next_server) = CONFIG
        .read()
        .unwrap() // TODO(ajf): don't unwrap
        .provisioning_server_ipv4
        .clone() {
        next_server.to_string()
    } else {
        "127.0.0.1".to_string()
    };

    let arm_http_client = format!(
        "http://{}:8080/public/blobs/internal/aarch64/ipxe.efi",
        url
    );
    let x86_http_client = format!(
        "http://{}:8080/public/blobs/internal/x86_64/ipxe.efi",
        url
    );

    let fqdn = if let Some(vendor_class) = &machine.vendor_class {
        let filename = match vendor_class {
            VendorClass {
                client_architecture: MachineArchitecture::EfiX64,
                client_type: MachineClientClass::PXEClient,
            } => "/blobs/internal/x86_64/grub.efi",
            VendorClass {
                client_architecture: MachineArchitecture::Arm64,
                client_type: MachineClientClass::PXEClient,
            } => "/blobs/internal/x86_64/grub.efi",
            VendorClass {
                client_architecture: MachineArchitecture::BiosX86,
                client_type: MachineClientClass::PXEClient,
            } => "/blobs/internal/x86_64/grub.kpxe",
            VendorClass {
                client_architecture: MachineArchitecture::EfiX64,
                client_type: MachineClientClass::HTTPClient,
            } => x86_http_client.as_str(),
            VendorClass {
                client_architecture: MachineArchitecture::Arm64,
                client_type: MachineClientClass::HTTPClient,
            } => arm_http_client.as_str(),
            VendorClass {
                client_architecture: MachineArchitecture::BiosX86,
                client_type: MachineClientClass::HTTPClient,
            } => unreachable!(), // BIOS never supports HTTPClient
        };

        Some(CString::new(filename).unwrap())
    } else {
        None
    };

    std::mem::forget(machine);

    fqdn.map(|f| f.into_raw())
        .or_else(|| Some(ptr::null_mut()))
        .unwrap()
}

#[no_mangle]
pub extern "C" fn machine_get_next_server(ctx: *mut Machine) -> u32 {
    assert!(!ctx.is_null());
    let machine = unsafe { Box::from_raw(ctx) };

    let ip_addr = if let Some(next_server) = CONFIG
        .read()
        .unwrap() // TODO(ajf): don't unwrap
        .provisioning_server_ipv4 {
        next_server.octets()
    } else {
        "127.0.0.1".to_string().parse::<Ipv4Addr>().unwrap().octets()
    };

    let ret = u32::from_be_bytes(ip_addr);

    std::mem::forget(machine);

    ret
}

#[no_mangle]
pub extern "C" fn machine_get_nameservers(ctx: *mut Machine) -> *mut libc::c_char {
    assert!(!ctx.is_null());
    let machine = unsafe { Box::from_raw(ctx) };

    let nameservers = CString::new(CONFIG.read().unwrap().nameservers.clone()).unwrap();
    debug!("Nameservers are {:?}", nameservers);

    std::mem::forget(machine);

    nameservers.into_raw()
}

#[no_mangle]
pub extern "C" fn machine_get_client_type(ctx: *mut Machine) -> *mut libc::c_char {
    assert!(!ctx.is_null());
    let machine = unsafe { Box::from_raw(ctx) };

    let vendor_class = if let Some(vendor_class) = &machine.vendor_class {
        let display = match vendor_class.client_type {
            MachineClientClass::PXEClient => "PXEClient", // This has to be blank or it will not dhcp
            MachineClientClass::HTTPClient => "HTTPClient",
        };
        CString::new(display).unwrap()
    } else {
        CString::new("").unwrap()
    };

    std::mem::forget(machine);

    vendor_class.into_raw()
}

#[no_mangle]
pub extern "C" fn machine_get_uuid(ctx: *mut Machine) -> *mut libc::c_char {
    assert!(!ctx.is_null());
    let machine = unsafe { Box::from_raw(ctx) };

    let uuid = if let Some(machine_interface_id) = &machine.inner.machine_interface_id {
        CString::new(machine_interface_id.to_string()).unwrap()
    } else {
        error!(
            "Found a host missing UUID, dumping everything we know about it: {:?}",
            &machine
        );
        CString::new("").unwrap()
    };

    std::mem::forget(machine);

    uuid.into_raw()
}

#[no_mangle]
pub extern "C" fn machine_get_broadcast_address(ctx: *mut Machine) -> u32 {
    assert!(!ctx.is_null());
    let machine = unsafe { Box::from_raw(ctx) };

    let maybe_prefix = machine.inner.prefix.parse::<IpNetwork>();

    // We parsed the prefix, so we can forget this memory
    std::mem::forget(machine);

    match maybe_prefix {
        Ok(prefix) => match prefix {
            IpNetwork::V4(prefix) => return u32::from_be_bytes(prefix.broadcast().octets()),
            IpNetwork::V6(prefix) => {
                error!(
                    "Prefix ({}) is an IPv6 network, which is not supported.",
                    prefix
                );
            }
        },
        Err(error) => {
            error!(
                "prefix value in deserialized protobuf is not an IP Network: {0}",
                error
            );
        }
    };

    return 0;
}

#[no_mangle]
pub extern "C" fn machine_free_filename(filename: *const libc::c_char) {
    unsafe {
        if filename.is_null() {
            return;
        }

        CString::from_raw(filename as *mut _)
    };
}

#[no_mangle]
pub extern "C" fn machine_free_client_type(client_type: *mut libc::c_char) {
    unsafe {
        if client_type.is_null() {
            return;
        }

        CString::from_raw(client_type)
    };
}

#[no_mangle]
pub extern "C" fn machine_free_uuid(uuid: *mut libc::c_char) {
    unsafe {
        if uuid.is_null() {
            return;
        }

        CString::from_raw(uuid)
    };
}

#[no_mangle]
pub extern "C" fn machine_free_fqdn(fqdn: *mut libc::c_char) {
    unsafe {
        if fqdn.is_null() {
            return;
        }

        CString::from_raw(fqdn)
    };
}

#[no_mangle]
pub extern "C" fn machine_free_nameservers(nameservers: *mut libc::c_char) {
    unsafe {
        if nameservers.is_null() {
            return;
        }

        CString::from_raw(nameservers)
    };
}

/// Invoke the discovery processs
///
/// # Safety
///
/// This function deferences a pointer to a Machine object which is an opaque pointer
/// consumed in C code.
///
#[no_mangle]
pub extern "C" fn machine_get_interface_subnet_mask(ctx: *mut Machine) -> u32 {
    assert!(!ctx.is_null());
    let machine = unsafe { Box::from_raw(ctx) };

    let maybe_prefix = machine.inner.prefix.parse::<IpNetwork>();

    // We parsed the prefix, so we can forget this memory
    std::mem::forget(machine);

    match maybe_prefix {
        Ok(prefix) => match prefix {
            IpNetwork::V4(prefix) => return u32::from_be_bytes(prefix.mask().octets()),
            IpNetwork::V6(prefix) => {
                error!(
                    "Prefix ({}) is an IPv6 network, which is not supported.",
                    prefix
                );
            }
        },
        Err(error) => {
            error!(
                "prefix value in deserialized protobuf is not an IP Network: {0}",
                error
            );
        }
    };

    return 0;
}

/// Free the Machine object.
///
/// # Safety
///
/// This function deferences a pointer to a Machine object which is an opaque pointer
/// consumed in C code.
///
/// This does not forget the memory afterwards, so the opaque pointer in the C code is now
/// unusable.
///
#[no_mangle]
pub extern "C" fn machine_free(ctx: *mut Machine) {
    if ctx.is_null() {
        return;
    }

    unsafe { Box::from_raw(ctx) };
}
