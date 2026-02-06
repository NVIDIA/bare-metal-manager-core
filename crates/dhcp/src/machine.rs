/*
 * SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
use std::ffi::CString;
use std::net::{IpAddr, Ipv4Addr};
use std::ptr;

use ::rpc::forge as rpc;
use ::rpc::forge_tls_client::{self, ApiConfig, ForgeClientConfig};
use MachineArchitecture::*;
use ipnetwork::IpNetwork;

use crate::CONFIG;
use crate::discovery::Discovery;
use crate::vendor_class::{MachineArchitecture, VendorClass};

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
        carbide_api_url: &str,
        vendor_class: Option<VendorClass>,
        client_config: &ForgeClientConfig,
    ) -> Result<Self, String> {
        let api_config = ApiConfig::new(carbide_api_url, client_config);
        match forge_tls_client::ForgeTlsClient::retry_build(&api_config).await {
            Ok(mut client) => {
                let request = tonic::Request::new(rpc::DhcpDiscovery {
                    mac_address: discovery.mac_address.to_string(),
                    relay_address: discovery.relay_address.to_string(),
                    link_address: discovery.link_select_address.map(|addr| addr.to_string()),
                    vendor_string: discovery.vendor_class.clone(),
                    circuit_id: discovery.circuit_id.clone(),
                    remote_id: discovery.remote_id.clone(),
                    desired_address: discovery.desired_address.clone(),
                });

                client
                    .discover_dhcp(request)
                    .await
                    .map(|response| Machine {
                        inner: response.into_inner(),
                        discovery_info: discovery,
                        vendor_class,
                    })
                    .map_err(|error| format!("unable to discover machine via Carbide: {error:?}"))
            }
            Err(err) => Err(format!("unable to connect to Carbide API: {err:?}")),
        }
    }

    pub fn booturl(&self) -> Option<&str> {
        self.inner.booturl.as_deref()
    }
}

/// Get the router address
///
/// # Safety
///
/// This function dereferences a pointer to a Machine object which is an opaque pointer
/// consumed in C code.
///
#[unsafe(no_mangle)]
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
        .parse::<IpAddr>();

    match maybe_gateway {
        Ok(gateway) => match gateway {
            IpAddr::V4(gateway) => return u32::from_be_bytes(gateway.octets()),
            IpAddr::V6(gateway) => {
                log::error!("Gateway ({gateway}) is an IPv6 address, which is not supported.");
            }
        },
        Err(error) => {
            log::error!("Gateway value in deserialized protobuf is not an IP Network: {error}");
        }
    };

    0
}

/// Invoke the discovery process
///
/// # Safety
/// This function dereferences a pointer to a Machine object which is an opaque pointer
/// consumed in C code.
///
#[unsafe(no_mangle)]
pub extern "C" fn machine_get_interface_address(ctx: *mut Machine) -> u32 {
    assert!(!ctx.is_null());
    let machine = unsafe { &mut *ctx };

    let maybe_address = machine.inner.address.parse::<IpAddr>();

    match maybe_address {
        Ok(address) => match address {
            IpAddr::V4(address) => return u32::from_be_bytes(address.octets()),
            IpAddr::V6(address) => {
                log::error!("Address ({address}) is an IPv6 address, which is not supported.");
            }
        },
        Err(error) => {
            log::error!("Address value in deserialized protobuf is not an IP Network: {error}");
        }
    };

    0
}

/// Get the machine fqdn
///
/// # Safety
/// This function checks for null pointer and unboxes into a machine object
///
#[unsafe(no_mangle)]
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
#[unsafe(no_mangle)]
pub extern "C" fn machine_get_filename(ctx: *mut Machine) -> *const libc::c_char {
    assert!(!ctx.is_null());
    let machine = unsafe { &mut *ctx };

    // If the API sent us the URL we should boot from, just use it.
    let url = if let Some(url) = machine.booturl() {
        url.to_string()
    } else {
        let arch = match &machine.vendor_class {
            None => {
                return ptr::null();
            }
            Some(v) if !v.is_netboot() => {
                return ptr::null();
            }
            Some(VendorClass { arch, .. }) => arch,
        };

        let base_url = if let Some(next_server) = CONFIG
            .read()
            .unwrap() // TODO(ajf): don't unwrap
            .provisioning_server_ipv4
        {
            next_server.to_string()
        } else {
            log::warn!("Could not retrieve provisioning-server-ipv4 configuration from Kea");
            return ptr::null();
        };

        match arch {
            EfiX64 => format!("http://{base_url}:8080/public/blobs/internal/x86_64/ipxe.efi"),
            Arm64 => format!("http://{base_url}:8080/public/blobs/internal/aarch64/ipxe.efi"),
            BiosX86 => {
                log::error!(
                    "Matched an HTTP client on a Legacy BIOS client, cannot provide HTTP boot URL {:?}",
                    &machine
                );
                return ptr::null();
            }
            Unknown => {
                log::error!(
                    "Matched an unknown architecture, cannot provide HTTP boot URL {:?}",
                    &machine
                );
                return ptr::null();
            }
        }
    };

    CString::new(url).unwrap().into_raw()
}

// IPv4 address of next-server (siaddr) as big endian int 32.
#[unsafe(no_mangle)]
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

#[unsafe(no_mangle)]
pub extern "C" fn machine_get_nameservers(ctx: *mut Machine) -> *mut libc::c_char {
    assert!(!ctx.is_null());

    let nameservers = CString::new(CONFIG.read().unwrap().nameservers.clone()).unwrap();
    log::debug!("Nameservers are {nameservers:?}");

    nameservers.into_raw()
}

#[unsafe(no_mangle)]
pub extern "C" fn machine_get_ntpservers(ctx: *mut Machine) -> *mut libc::c_char {
    assert!(!ctx.is_null());

    let ntpservers = CString::new(CONFIG.read().unwrap().ntpservers.clone()).unwrap();
    log::debug!("Ntp servers are {ntpservers:?}");

    ntpservers.into_raw()
}

#[unsafe(no_mangle)]
pub extern "C" fn machine_get_mqtt_server(ctx: *mut Machine) -> *mut libc::c_char {
    assert!(!ctx.is_null());

    match CONFIG.read().unwrap().mqtt_server.clone() {
        Some(mqtt_server) => {
            log::debug!("MQTT server is {mqtt_server:?}");
            CString::new(mqtt_server).unwrap().into_raw()
        }
        None => {
            log::debug!("MQTT server is unset");
            ptr::null_mut()
        }
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn machine_get_client_type(ctx: *mut Machine) -> *mut libc::c_char {
    assert!(!ctx.is_null());
    let machine = unsafe { &mut *ctx };
    let vendor_class = match &machine.vendor_class {
        None => CString::new("").unwrap(),
        Some(vc) => CString::new(vc.id.clone()).unwrap(),
    };
    vendor_class.into_raw()
}

#[unsafe(no_mangle)]
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

#[unsafe(no_mangle)]
pub extern "C" fn machine_get_broadcast_address(ctx: *mut Machine) -> u32 {
    assert!(!ctx.is_null());
    let machine = unsafe { &mut *ctx };

    let maybe_prefix = machine.inner.prefix.parse::<IpNetwork>();

    match maybe_prefix {
        Ok(prefix) => match prefix {
            IpNetwork::V4(prefix) => return u32::from_be_bytes(prefix.broadcast().octets()),
            IpNetwork::V6(prefix) => {
                log::error!("Prefix ({prefix}) is an IPv6 network, which is not supported.");
            }
        },
        Err(error) => {
            log::error!("prefix value in deserialized protobuf is not an IP Network: {error}");
        }
    };

    0
}

#[unsafe(no_mangle)]
pub extern "C" fn machine_free_filename(filename: *const libc::c_char) {
    unsafe {
        if filename.is_null() {
            return;
        }

        drop(CString::from_raw(filename as *mut _))
    };
}

#[unsafe(no_mangle)]
pub extern "C" fn machine_free_client_type(client_type: *mut libc::c_char) {
    unsafe {
        if client_type.is_null() {
            return;
        }

        drop(CString::from_raw(client_type))
    };
}

#[unsafe(no_mangle)]
pub extern "C" fn machine_free_uuid(uuid: *mut libc::c_char) {
    unsafe {
        if uuid.is_null() {
            return;
        }

        drop(CString::from_raw(uuid))
    };
}

#[unsafe(no_mangle)]
pub extern "C" fn machine_free_fqdn(fqdn: *mut libc::c_char) {
    unsafe {
        if fqdn.is_null() {
            return;
        }

        drop(CString::from_raw(fqdn))
    };
}

#[unsafe(no_mangle)]
pub extern "C" fn machine_free_nameservers(nameservers: *mut libc::c_char) {
    unsafe {
        if nameservers.is_null() {
            return;
        }

        drop(CString::from_raw(nameservers))
    };
}

#[unsafe(no_mangle)]
pub extern "C" fn machine_free_ntpservers(ntpservers: *mut libc::c_char) {
    unsafe {
        if ntpservers.is_null() {
            return;
        }

        drop(CString::from_raw(ntpservers))
    };
}

/// Invoke the discovery process
///
/// # Safety
///
/// This function dereferences a pointer to a Machine object which is an opaque pointer
/// consumed in C code.
///
#[unsafe(no_mangle)]
pub extern "C" fn machine_get_interface_subnet_mask(ctx: *mut Machine) -> u32 {
    assert!(!ctx.is_null());
    let machine = unsafe { &mut *ctx };

    let maybe_prefix = machine.inner.prefix.parse::<IpNetwork>();

    match maybe_prefix {
        Ok(prefix) => match prefix {
            IpNetwork::V4(prefix) => return u32::from_be_bytes(prefix.mask().octets()),
            IpNetwork::V6(prefix) => {
                log::error!("Prefix ({prefix}) is an IPv6 network, which is not supported.");
            }
        },
        Err(error) => {
            log::error!("prefix value in deserialized protobuf is not an IP Network: {error}");
        }
    };

    0
}

/// Extract MTU from Machine object. We got it in the grpc response in discovery_fetch_machine.
/// https://jirasw.nvidia.com/browse/FORGE-2443
#[unsafe(no_mangle)]
pub extern "C" fn machine_get_interface_mtu(ctx: *mut Machine) -> u16 {
    unsafe { (*ctx).inner.mtu as u16 }
}

/// Free the Machine object.
///
/// # Safety
///
/// This function dereferences a pointer to a Machine object which is an opaque pointer
/// consumed in C code.
///
/// This does not forget the memory afterwards, so the opaque pointer in the C code is now
/// unusable.
///
#[unsafe(no_mangle)]
pub extern "C" fn machine_free(ctx: *mut Machine) {
    if ctx.is_null() {
        return;
    }

    unsafe {
        drop(Box::from_raw(ctx));
    }
}

#[cfg(test)]
mod test {
    use std::ffi::CString;
    use std::net::Ipv4Addr;
    use std::str::FromStr;

    use rpc::forge as rpc;

    use crate::discovery::Discovery;
    use crate::machine::{Machine, machine_get_filename};
    use crate::vendor_class::VendorClass;

    #[test]
    fn test_use_booturl_internal() {
        crate::carbide_set_config_next_server_ipv4("127.0.0.1".parse::<Ipv4Addr>().unwrap().into());

        let mut machine = Box::new(Machine {
            inner: rpc::DhcpRecord::default(),
            discovery_info: Discovery {
                relay_address: "127.0.0.1".parse().unwrap(),
                mac_address: "00:00:00:00:00:00".parse().unwrap(),
                _client_system: None,
                vendor_class: None,
                link_select_address: "127.0.0.1".parse().ok(),
                circuit_id: None,
                remote_id: None,
                desired_address: None,
            },
            vendor_class: VendorClass::from_str("HTTPClient:Arch:00011:UNDI:003000")
                .unwrap()
                .into(),
        });

        let out = machine_get_filename(&mut *machine);

        assert_ne!(out, std::ptr::null());

        let cstr = unsafe { CString::from_raw(out as *mut _) };

        assert_eq!(
            cstr,
            CString::new("http://127.0.0.1:8080/public/blobs/internal/aarch64/ipxe.efi").unwrap()
        );
    }

    #[test]
    fn test_use_booturl_from_api() {
        let dhcp_record = rpc::DhcpRecord {
            booturl: Some("https://foobar".to_string()),
            ..Default::default()
        };

        let mut machine = Box::new(Machine {
            inner: dhcp_record,
            discovery_info: Discovery {
                relay_address: "127.0.0.1".parse::<Ipv4Addr>().unwrap(),
                mac_address: "00:00:00:00:00:00".parse().unwrap(),
                _client_system: None,
                vendor_class: None,
                link_select_address: "127.0.0.1".parse::<Ipv4Addr>().ok(),
                circuit_id: None,
                remote_id: None,
                desired_address: None,
            },
            vendor_class: VendorClass::from_str("HTTPClient:Arch:00011:UNDI:003000")
                .unwrap()
                .into(),
        });

        let out = machine_get_filename(&mut *machine);

        assert_ne!(out, std::ptr::null());

        let cstr = unsafe { CString::from_raw(out as *mut _) };

        assert_eq!(cstr, CString::new("https://foobar").unwrap());
    }
}
