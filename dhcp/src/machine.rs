/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2023 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */
use std::ffi::CString;
use std::net::Ipv4Addr;
use std::primitive::u32;
use std::ptr;

use ::rpc::forge as rpc;
use ::rpc::forge_tls_client;
use ipnetwork::IpNetwork;

use crate::discovery::Discovery;
use crate::vendor_class::{MachineArchitecture, VendorClass};
use crate::CONFIG;

/// Machine: a machine that's currently trying to boot something
///
/// This just stores the protobuf DHCP record and the discovery info the client used so we can add
/// additional constraints (options) to and from the client.
///
#[derive(Debug, Clone)]
pub struct Machine {
    pub inner: rpc::DhcpRecord,
    pub discovery_info: Discovery,
    pub vendor_class: Option<VendorClass>,
}

impl Machine {
    pub async fn try_fetch(
        discovery: Discovery,
        url: &str,
        vendor_class: Option<VendorClass>,
        forge_root_ca_path: Option<String>,
    ) -> Result<Self, String> {
        match forge_tls_client::ForgeTlsClient::new(forge_root_ca_path)
            .connect(url)
            .await
        {
            Ok(mut client) => {
                let request = tonic::Request::new(rpc::DhcpDiscovery {
                    mac_address: discovery.mac_address.to_string(),
                    relay_address: discovery.relay_address.to_string(),
                    link_address: discovery.link_select_address.map(|addr| addr.to_string()),
                    vendor_string: discovery.vendor_class.clone(),
                    circuit_id: discovery.circuit_id.clone(),
                });

                client
                    .discover_dhcp(request)
                    .await
                    .map(|response| Machine {
                        inner: response.into_inner(),
                        discovery_info: discovery,
                        vendor_class,
                    })
                    .map_err(|error| format!("unable to discover machine via Carbide: {:?}", error))
            }
            Err(err) => Err(format!("unable to connect to Carbide API: {:?}", err)),
        }
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
    let machine = unsafe { &mut *ctx };

    // todo(ajf): I guess??
    let default_router = "0.0.0.0".to_string();

    let maybe_gateway = machine
        .inner
        .gateway
        .as_ref()
        .unwrap_or_else(|| {
            log::warn!(
                "No gateway provided for machine interface: {:?}",
                &machine.inner.machine_interface_id
            );
            &default_router
        })
        .parse::<IpNetwork>();

    match maybe_gateway {
        Ok(gateway) => match gateway {
            IpNetwork::V4(gateway) => return u32::from_be_bytes(gateway.ip().octets()),
            IpNetwork::V6(gateway) => {
                log::error!(
                    "Gateway ({}) is an IPv6 address, which is not supported.",
                    gateway
                );
            }
        },
        Err(error) => {
            log::error!(
                "Gateway value in deserialized protobuf is not an IP Network: {0}",
                error
            );
        }
    };

    0
}

/// Invoke the discovery process
///
/// # Safety
/// This function deferences a pointer to a Machine object which is an opaque pointer
/// consumed in C code.
///
#[no_mangle]
pub extern "C" fn machine_get_interface_address(ctx: *mut Machine) -> u32 {
    assert!(!ctx.is_null());
    let machine = unsafe { &mut *ctx };

    let maybe_address = machine.inner.address.parse::<IpNetwork>();

    match maybe_address {
        Ok(address) => match address {
            IpNetwork::V4(address) => return u32::from_be_bytes(address.ip().octets()),
            IpNetwork::V6(address) => {
                log::error!(
                    "Address ({}) is an IPv6 address, which is not supported.",
                    address
                );
            }
        },
        Err(error) => {
            log::error!(
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
    let machine = unsafe { &mut *ctx };

    let fqdn = CString::new(&machine.inner.fqdn[..]).unwrap();

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
    let machine = unsafe { &mut *ctx };
    let arch = match &machine.vendor_class {
        None => {
            return ptr::null();
        }
        Some(v) if !v.is_netboot() => {
            return ptr::null();
        }
        Some(VendorClass { arch, .. }) => arch,
    };

    let url = if let Some(next_server) = CONFIG
        .read()
        .unwrap() // TODO(ajf): don't unwrap
        .provisioning_server_ipv4
    {
        next_server.to_string()
    } else {
        "127.0.0.1".to_string()
    };

    use MachineArchitecture::*;
    let fqdn = match arch {
        EfiX64 => format!("http://{}:8080/public/blobs/internal/x86_64/ipxe.efi", url),
        Arm64 => format!("http://{}:8080/public/blobs/internal/aarch64/ipxe.efi", url),
        BiosX86 => unreachable!(), // BIOS never supports HTTPClient
    };
    CString::new(fqdn).unwrap().into_raw()
}

// IPv4 address of next-server (siaddr) as big endian int 32.
#[no_mangle]
pub extern "C" fn machine_get_next_server(ctx: *mut Machine) -> u32 {
    assert!(!ctx.is_null());
    let ip_addr = if let Some(next_server) = CONFIG
        .read()
        .unwrap() // TODO(ajf): don't unwrap
        .provisioning_server_ipv4
    {
        next_server.octets()
    } else {
        "127.0.0.1"
            .to_string()
            .parse::<Ipv4Addr>()
            .unwrap()
            .octets()
    };

    u32::from_be_bytes(ip_addr)
}

#[no_mangle]
pub extern "C" fn machine_get_nameservers(ctx: *mut Machine) -> *mut libc::c_char {
    assert!(!ctx.is_null());

    let nameservers = CString::new(CONFIG.read().unwrap().nameservers.clone()).unwrap();
    log::debug!("Nameservers are {:?}", nameservers);

    nameservers.into_raw()
}

#[no_mangle]
pub extern "C" fn machine_get_ntpservers(ctx: *mut Machine) -> *mut libc::c_char {
    assert!(!ctx.is_null());

    let ntpservers = CString::new(CONFIG.read().unwrap().ntpserver.clone()).unwrap();
    log::debug!("Ntp servers are {:?}", ntpservers);

    ntpservers.into_raw()
}

#[no_mangle]
pub extern "C" fn machine_get_client_type(ctx: *mut Machine) -> *mut libc::c_char {
    assert!(!ctx.is_null());
    let machine = unsafe { &mut *ctx };
    let vendor_class = match &machine.vendor_class {
        None => CString::new("").unwrap(),
        Some(vc) => CString::new(vc.id.clone()).unwrap(),
    };
    vendor_class.into_raw()
}

#[no_mangle]
pub extern "C" fn machine_get_uuid(ctx: *mut Machine) -> *mut libc::c_char {
    assert!(!ctx.is_null());
    let machine = unsafe { &mut *ctx };

    let uuid = if let Some(machine_interface_id) = &machine.inner.machine_interface_id {
        CString::new(machine_interface_id.to_string()).unwrap()
    } else {
        log::debug!(
            "Found a host missing UUID (Possibly a Instance), dumping everything we know about it: {:?}",
            &machine
        );
        CString::new("").unwrap()
    };

    uuid.into_raw()
}

#[no_mangle]
pub extern "C" fn machine_get_broadcast_address(ctx: *mut Machine) -> u32 {
    assert!(!ctx.is_null());
    let machine = unsafe { &mut *ctx };

    let maybe_prefix = machine.inner.prefix.parse::<IpNetwork>();

    match maybe_prefix {
        Ok(prefix) => match prefix {
            IpNetwork::V4(prefix) => return u32::from_be_bytes(prefix.broadcast().octets()),
            IpNetwork::V6(prefix) => {
                log::error!(
                    "Prefix ({}) is an IPv6 network, which is not supported.",
                    prefix
                );
            }
        },
        Err(error) => {
            log::error!(
                "prefix value in deserialized protobuf is not an IP Network: {0}",
                error
            );
        }
    };

    0
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

#[no_mangle]
pub extern "C" fn machine_free_ntpserver(ntpserver: *mut libc::c_char) {
    unsafe {
        if ntpserver.is_null() {
            return;
        }

        CString::from_raw(ntpserver)
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
    let machine = unsafe { &mut *ctx };

    let maybe_prefix = machine.inner.prefix.parse::<IpNetwork>();

    match maybe_prefix {
        Ok(prefix) => match prefix {
            IpNetwork::V4(prefix) => return u32::from_be_bytes(prefix.mask().octets()),
            IpNetwork::V6(prefix) => {
                log::error!(
                    "Prefix ({}) is an IPv6 network, which is not supported.",
                    prefix
                );
            }
        },
        Err(error) => {
            log::error!(
                "prefix value in deserialized protobuf is not an IP Network: {0}",
                error
            );
        }
    };

    0
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
