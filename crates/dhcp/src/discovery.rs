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
use std::ffi::{CStr, c_char};
use std::net::{IpAddr, Ipv4Addr};

use derive_builder::Builder;
use mac_address::MacAddress;

use crate::machine::Machine;
use crate::metrics::set_service_healthy;
use crate::vendor_class::VendorClass;
use crate::{CONFIG, CarbideDhcpContext, cache, tls};

/// Enumerates results of setting discovery options on the Builder
#[repr(C)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum DiscoveryBuilderResult {
    Success = 0,
    InvalidDiscoveryBuilderPointer = 1,
    InvalidMacAddress = 2,
    InvalidVendorClass = 3,
    InvalidMachinePointer = 4,
    BuilderError = 5,
    FetchMachineError = 6,
    InvalidCircuitId = 7,
    TooManyFailuresError = 8,
}

#[unsafe(no_mangle)]
pub extern "C" fn discovery_builder_result_as_str(result: DiscoveryBuilderResult) -> *const c_char {
    // If you add a variant here, please don't forget adding \0 at the end of the
    // string to make it null terminated and compatible to what C expects
    CStr::from_bytes_with_nul(
        match result {
            DiscoveryBuilderResult::Success => "Success\0",
            DiscoveryBuilderResult::InvalidDiscoveryBuilderPointer => {
                "InvalidDiscoveryBuilderPointer\0"
            }
            DiscoveryBuilderResult::InvalidMacAddress => "InvalidMacAddress\0",
            DiscoveryBuilderResult::InvalidVendorClass => "InvalidVendorClass\0",
            DiscoveryBuilderResult::InvalidMachinePointer => "InvalidMachinePointer\0",
            DiscoveryBuilderResult::BuilderError => "BuilderError\0",
            DiscoveryBuilderResult::FetchMachineError => "FetchMachineError\0",
            DiscoveryBuilderResult::InvalidCircuitId => "InvalidCircuitId\0",
            DiscoveryBuilderResult::TooManyFailuresError => "TooManyFailuresError\0",
        }
        .as_bytes(),
    )
    .unwrap_or_default()
    .as_ptr()
}

#[derive(Debug, Clone, Builder)]
pub struct Discovery {
    pub(crate) relay_address: Ipv4Addr,
    pub(crate) mac_address: MacAddress,

    #[builder(setter(into, strip_option, name = "client_system"), default)]
    pub(crate) _client_system: Option<u16>,

    #[builder(setter(into, strip_option), default)]
    pub(crate) vendor_class: Option<String>,

    #[builder(setter(into, strip_option), default)]
    pub(crate) link_select_address: Option<Ipv4Addr>,

    #[builder(setter(into, strip_option), default)]
    pub(crate) circuit_id: Option<String>,

    #[builder(setter(into, strip_option), default)]
    pub(crate) remote_id: Option<String>,

    #[builder(setter(into, strip_option), default)]
    pub(crate) desired_address: Option<String>,
}

#[repr(C)]
pub struct DiscoveryBuilderFFI(());

/// Allocate a new struct to fill in the discovery information from the DHCP packet in Kea
///
/// This is an "opaque" pointer to rust data, which must be freed by rust data, and to keep the FFI
/// interface simple there's a series of discovery_set_*() functions that set the data in this
/// struct.
///
/// The returned object must either be consumed by calling
/// `discovery_fetch_machine`, or freed by calling `discovery_builder_free`.
#[unsafe(no_mangle)]
#[allow(clippy::box_default)] // the Builder does not and cannot implement default, but clippy wants it to because they named the generated function "default".
pub extern "C" fn discovery_builder_allocate() -> *mut DiscoveryBuilderFFI {
    Box::into_raw(Box::new(DiscoveryBuilder::default())) as _
}

unsafe fn marshal_discovery_ffi<F>(
    builder: *mut DiscoveryBuilderFFI,
    f: F,
) -> DiscoveryBuilderResult
where
    F: FnOnce(&mut DiscoveryBuilder) -> DiscoveryBuilderResult,
{
    unsafe {
        if builder.is_null() {
            return DiscoveryBuilderResult::InvalidDiscoveryBuilderPointer;
        }

        let builder = &mut *(builder as *mut DiscoveryBuilder);

        f(builder)
    }
}

/// Fill the `client_system` portion of the discovery object
///
/// # Safety
///
/// This function is only safe to be called on a `ctx` which is either a null pointer
/// or a valid `DiscoveryBuilderFFI` object.
///
#[unsafe(no_mangle)]
pub unsafe extern "C" fn discovery_set_client_system(
    ctx: *mut DiscoveryBuilderFFI,
    client_system: u16,
) -> DiscoveryBuilderResult {
    unsafe {
        marshal_discovery_ffi(ctx, |builder| {
            builder.client_system(client_system);
            DiscoveryBuilderResult::Success
        })
    }
}

/// Fill the `vendor_class` portion of the discovery object
///
/// # Safety
///
/// This function is only safe to be called on a `ctx` which is either a null pointer
/// or a valid `DiscoveryBuilderFFI` object.
///
#[unsafe(no_mangle)]
pub unsafe extern "C" fn discovery_set_vendor_class(
    ctx: *mut DiscoveryBuilderFFI,
    vendor_class: *const libc::c_char,
) -> DiscoveryBuilderResult {
    unsafe {
        let vendor_class = match CStr::from_ptr(vendor_class).to_str() {
            Ok(string) => string.to_owned(),
            Err(error) => {
                log::error!("Invalid UTF-8 byte string for vendor_class: {error}");
                return DiscoveryBuilderResult::InvalidVendorClass;
            }
        };

        marshal_discovery_ffi(ctx, |builder| {
            builder.vendor_class(vendor_class);
            DiscoveryBuilderResult::Success
        })
    }
}

/// Fill the `link select` portion of the Discovery object with an IP(v4) address
///
/// # Safety
///
/// This function is only safe to be called on a `ctx` which is either a null pointer
/// or a valid `DiscoveryBuilderFFI` object.
///
#[unsafe(no_mangle)]
pub unsafe extern "C" fn discovery_set_link_select(
    ctx: *mut DiscoveryBuilderFFI,
    link_select: u32,
) -> DiscoveryBuilderResult {
    unsafe {
        marshal_discovery_ffi(ctx, |builder| {
            builder.link_select_address(Ipv4Addr::from(link_select.to_be_bytes()));
            DiscoveryBuilderResult::Success
        })
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn discovery_set_desired_address(
    ctx: *mut DiscoveryBuilderFFI,
    desired_address: *const libc::c_char,
) -> DiscoveryBuilderResult {
    unsafe {
        let desired_address = match CStr::from_ptr(desired_address).to_str() {
            Ok(string) => string.to_owned(),
            Err(error) => {
                log::error!("Invalid UTF-8 byte string for desired_address: {error}");
                return DiscoveryBuilderResult::InvalidVendorClass;
            }
        };

        marshal_discovery_ffi(ctx, |builder| {
            builder.desired_address(desired_address);
            DiscoveryBuilderResult::Success
        })
    }
}

/// Fill the `circuit id (vlanid)` portion of the Discovery object with an String
///
/// # Safety
///
/// This function is only safe to be called on a `ctx` which is either a null pointer
/// or a valid `DiscoveryBuilderFFI` object.
///
#[unsafe(no_mangle)]
pub unsafe extern "C" fn discovery_set_circuit_id(
    ctx: *mut DiscoveryBuilderFFI,
    circuit_id: *const libc::c_char,
) -> DiscoveryBuilderResult {
    unsafe {
        let circuit_id = match CStr::from_ptr(circuit_id).to_str() {
            Ok(string) => string.to_owned(),
            Err(error) => {
                log::error!("Invalid UTF-8 byte string for circuit_id: {error}");
                return DiscoveryBuilderResult::InvalidCircuitId;
            }
        };

        marshal_discovery_ffi(ctx, |builder| {
            builder.circuit_id(circuit_id);
            DiscoveryBuilderResult::Success
        })
    }
}

/// Fill the `remote_id` portion of the Discovery object with an String
///
/// # Safety
///
/// This function is only safe to be called on a `ctx` which is either a null pointer
/// or a valid `DiscoveryBuilderFFI` object.
///
#[unsafe(no_mangle)]
pub unsafe extern "C" fn discovery_set_remote_id(
    ctx: *mut DiscoveryBuilderFFI,
    remote_id: *const libc::c_char,
) -> DiscoveryBuilderResult {
    unsafe {
        let remote_id = match CStr::from_ptr(remote_id).to_str() {
            Ok(string) => string.to_owned(),
            Err(error) => {
                log::error!("Invalid UTF-8 byte string for remote_id: {error}");
                return DiscoveryBuilderResult::InvalidCircuitId;
            }
        };

        marshal_discovery_ffi(ctx, |builder| {
            builder.remote_id(remote_id);
            DiscoveryBuilderResult::Success
        })
    }
}

/// Fill the `relay` portion of the Discovery object with an IP(v4) address
///
/// # Safety
///
/// This function is only safe to be called on a `ctx` which is either a null pointer
/// or a valid `DiscoveryBuilderFFI` object.
///
#[unsafe(no_mangle)]
pub unsafe extern "C" fn discovery_set_relay(
    ctx: *mut DiscoveryBuilderFFI,
    relay: u32,
) -> DiscoveryBuilderResult {
    unsafe {
        marshal_discovery_ffi(ctx, |builder| {
            builder.relay_address(Ipv4Addr::from(relay.to_be_bytes()));
            DiscoveryBuilderResult::Success
        })
    }
}

/// Fill the `mac_address` portion of the Discovery object with an IP(v4) address
///
/// # Safety
///
/// This function is only safe to be called on a `ctx` which is either a null pointer
/// or a valid `DiscoveryBuilderFFI` object.
///
/// `raw_parts` and `size` must describe a valid memory holding 6 bytes which make
/// up a MAC address.
///
#[unsafe(no_mangle)]
pub unsafe extern "C" fn discovery_set_mac_address(
    ctx: *mut DiscoveryBuilderFFI,
    mac_address_ptr: *const u8,
    mac_address_len: usize,
) -> DiscoveryBuilderResult {
    unsafe {
        // The contract of this function is that the pointer/length pairs fors a valid
        // byte array, so we can use `slice_from_raw_parts` to convert.
        // `.try_into()` will check the address is exactly 6 bytes long
        let mac_address_bytes: [u8; 6] =
            match std::slice::from_raw_parts(mac_address_ptr, mac_address_len).try_into() {
                Ok(bytes) => bytes,
                Err(_) => {
                    return DiscoveryBuilderResult::InvalidMacAddress;
                }
            };

        let mac = MacAddress::new(mac_address_bytes);
        marshal_discovery_ffi(ctx, |builder| {
            builder.mac_address(mac);
            DiscoveryBuilderResult::Success
        })
    }
}

/// Utilizes the DiscoveryBuilder to fetch a machine
///
/// If the method returns `DiscoveryBuilderResult::Success`, then the pointer
/// for a `Machine` handle will be written to `machine_ptr`. `machine_ptr` is an
/// output parameter for a `Machine` pointer.
///
/// This function is only safe to be called on a `ctx` which is either a null pointer
/// or a valid `DiscoveryBuilderFFI` object.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn discovery_fetch_machine(
    ctx: *mut DiscoveryBuilderFFI,
    machine_ptr_out: *mut *mut Machine,
) -> DiscoveryBuilderResult {
    let url = &CONFIG
        .read()
        .unwrap() // TODO(ajf): don't unwrap
        .api_endpoint;

    unsafe { discovery_fetch_machine_at(ctx, machine_ptr_out, url) }
}

unsafe fn discovery_fetch_machine_at(
    ctx: *mut DiscoveryBuilderFFI,
    machine_ptr_out: *mut *mut Machine,
    url: &str,
) -> DiscoveryBuilderResult {
    unsafe {
        if machine_ptr_out.is_null() {
            return DiscoveryBuilderResult::InvalidMachinePointer;
        }
        *machine_ptr_out = std::ptr::null_mut();

        marshal_discovery_ffi(ctx, |builder| {
            let discovery = match builder.build() {
                Ok(discovery) => discovery,
                Err(err) => {
                    log::info!("Error compiling the discovery builder object: {err}");
                    return DiscoveryBuilderResult::BuilderError;
                }
            };

            let mac_address = discovery.mac_address;
            let circuit_id = discovery.circuit_id.clone();
            let remote_id = discovery.remote_id.clone();
            let desired_address = discovery.desired_address.clone();
            let addr_for_dhcp = IpAddr::V4(
                discovery
                    .link_select_address
                    .unwrap_or(discovery.relay_address),
            );

            // try to parse request vendor class identifier
            let vendor_class = match discovery.vendor_class {
                Some(ref vendor_class) => match vendor_class.parse::<VendorClass>() {
                    Ok(vc) => Some(vc),
                    Err(err) => {
                        log::warn!("error parsing vendor class: {vendor_class} {err:?}");
                        return DiscoveryBuilderResult::InvalidVendorClass;
                    }
                },
                None => None,
            };
            let vendor_id = match &vendor_class {
                Some(vc) => vc.id.as_str(),
                None => "",
            };

            let desired_ip = match &desired_address {
                Some(di) => di.as_str(),
                None => "",
            };

            let mut cache_entry_status = cache::CacheEntryStatus::DiscoveryFailing(0);
            if let Some(cache_entry) = cache::get(
                mac_address,
                addr_for_dhcp,
                &circuit_id,
                &remote_id,
                vendor_id,
            ) {
                // We return the cached response if it's a positive cache entry, or an error if it's a negative one.
                match cache_entry.status {
                    cache::CacheEntryStatus::ValidEntry(machine) => {
                        log::info!(
                            "returning cached response for ({mac_address}, {addr_for_dhcp}, {circuit_id:?}, {vendor_id} {desired_ip})."
                        );
                        *machine_ptr_out = Box::into_raw(machine);
                        return DiscoveryBuilderResult::Success;
                    }
                    cache::CacheEntryStatus::DiscoveryFailing(count) => {
                        log::info!(
                            "retrying carbide-api for ({mac_address}, {addr_for_dhcp}, {circuit_id:?}, {vendor_id} {desired_ip}). failure count: {count}."
                        );
                        cache_entry_status = cache_entry.status;
                    }
                    cache::CacheEntryStatus::DiscoveryFailed => {
                        log::info!(
                            "too many failures for ({mac_address}, {addr_for_dhcp}, {circuit_id:?}, {vendor_id} {desired_ip})."
                        );
                        return DiscoveryBuilderResult::TooManyFailuresError;
                    }
                }
            }

            // Spawn a tokio runtime and schedule the API connection and machine retrieval to an async
            // thread. This is required because tonic is async but this code generally is not.
            //
            // TODO(ajf): how to reason about FFI code with async.
            //
            let runtime: &tokio::runtime::Runtime = CarbideDhcpContext::get_tokio_runtime();

            let forge_client_config = tls::build_forge_client_config();

            match runtime.block_on(Machine::try_fetch(
                discovery,
                url,
                vendor_class.clone(),
                &forge_client_config,
            )) {
                Ok(machine) => {
                    // If any DHCP record had been invalidated after the KEA process started,
                    // KEAs internal cache (not the Rust cache) might be in inconsistent state.
                    // Since we don't have any API to invalidate the KEA cache we restart
                    // the process. This will happen very rarely, since Interface deletions
                    // in Forge are not common.
                    // See https://nvbugspro.nvidia.com/bug/4792034 for details
                    if let Some(last_invalidation) = machine.inner.last_invalidation_time.as_ref() {
                        let startup_time = CONFIG.read().unwrap().startup_time;

                        if let Ok(last_invalidation) =
                            chrono::DateTime::<chrono::Utc>::try_from(*last_invalidation)
                            && last_invalidation >= startup_time
                        {
                            log::error!(
                                "Restarting KEA since invalidation was reported by Carbide. Startup: {}. Last_Invalidation: {}",
                                startup_time.to_rfc3339(),
                                last_invalidation.to_rfc3339()
                            );
                            // Setting service status to unhealty, in case if gracefull shutdown fails, other process would need to restart it
                            // on failed probe
                            set_service_healthy(false);
                            // Try to gracefully shutdown dhcp server, this would call all webhooks and properly shutdown hook library
                            libc::kill(libc::getpid(), libc::SIGTERM);
                        }
                    }

                    cache::put(
                        mac_address,
                        addr_for_dhcp,
                        circuit_id,
                        remote_id,
                        vendor_id,
                        cache::CacheEntryStatus::ValidEntry(Box::new(machine.clone())),
                    );
                    *machine_ptr_out = Box::into_raw(Box::new(machine));
                    DiscoveryBuilderResult::Success
                }
                Err(e_str) => {
                    log::error!(
                        "Error getting info back from the machine discovery: mac={mac_address} addr={addr_for_dhcp} err={e_str} api_url={url}"
                    );
                    cache::put(
                        mac_address,
                        addr_for_dhcp,
                        circuit_id,
                        remote_id,
                        vendor_id,
                        cache_entry_status.increment_fails(),
                    );
                    DiscoveryBuilderResult::FetchMachineError
                }
            }
        })
    }
}

/// Free the Discovery Builder object.
///
/// # Safety
///
/// This function dereferences a pointer to a Discovery object which is an opaque pointer
/// consumed in C code.
///
/// This does not forget the memory afterwards, so the opaque pointer in the C code is now
/// unusable.
///
#[unsafe(no_mangle)]
pub unsafe extern "C" fn discovery_builder_free(ctx: *mut DiscoveryBuilderFFI) {
    unsafe {
        drop(Box::from_raw(ctx as *mut DiscoveryBuilder));
    }
}

#[cfg(test)]
mod tests {
    use std::ptr::null_mut;
    use std::thread;

    use super::*;
    use crate::mock_api_server;

    // Basic test passing null pointers
    #[test]
    fn test_discovery_fetch_machine_handles_null() {
        unsafe {
            assert_eq!(
                discovery_fetch_machine(null_mut(), null_mut()),
                DiscoveryBuilderResult::InvalidMachinePointer
            );

            let mut out = null_mut();
            assert_eq!(
                discovery_fetch_machine(null_mut(), &mut out),
                DiscoveryBuilderResult::InvalidDiscoveryBuilderPointer
            );
        }
    }

    // Test the success case of calling API server and test the cache.
    #[test]
    fn test_discovery_fetch_machine_success() {
        // Start the mock API server, spawning a task to run hyper.
        // We call block_on in discovery_fetch_machine_at, which allows hyper to make progress.
        let rt: &tokio::runtime::Runtime = CarbideDhcpContext::get_tokio_runtime();
        let api_server = rt.block_on(mock_api_server::MockAPIServer::start());

        // Input packet, found by printing a real one
        let builder_ffi = discovery_builder_allocate();
        unsafe {
            marshal_discovery_ffi(builder_ffi, |builder| {
                builder.relay_address([172, 20, 0, 11].into());
                builder.mac_address(MacAddress::new([2, 66, 172, 20, 0, 42]));
                builder.circuit_id("eth0");
                DiscoveryBuilderResult::Success
            });
        }

        // Pointer to result will go here
        let mut out = null_mut();

        // Test!
        let res = unsafe {
            discovery_fetch_machine_at(builder_ffi, &mut out, api_server.local_http_addr())
        };
        assert_eq!(res, DiscoveryBuilderResult::Success);

        // Check
        let machine = unsafe { &*out };
        assert!(mock_api_server::matches_mock_response(machine));
        assert_eq!(
            api_server.calls_for(mock_api_server::ENDPOINT_DISCOVER_DHCP),
            1
        );

        // Call it again
        let res = unsafe {
            discovery_fetch_machine_at(builder_ffi, &mut out, api_server.local_http_addr())
        };
        // .. still succeeds and is correct
        let machine = unsafe { &*out };
        assert_eq!(res, DiscoveryBuilderResult::Success);
        assert!(mock_api_server::matches_mock_response(machine));
        // .. but we used the cache so only one backend call was made
        assert_eq!(
            api_server.calls_for(mock_api_server::ENDPOINT_DISCOVER_DHCP),
            1
        );

        // Cleanup
        unsafe {
            discovery_builder_free(builder_ffi);
        }
    }

    // Run many basic discovery_fetch_machine tests concurrently
    #[test]
    fn test_discovery_fetch_machine_multi_threading() {
        // Start the mock API server
        let rt: &tokio::runtime::Runtime = CarbideDhcpContext::get_tokio_runtime();
        let api_server = rt.block_on(mock_api_server::MockAPIServer::start());

        let endpoint_url = api_server.local_http_addr();
        thread::scope(|s| {
            let mut handles = Vec::with_capacity(10);
            for last_mac in 0..10 {
                handles.push(s.spawn(move || {
                    for _ in 0..10 {
                        multi_threading_test_inner(last_mac, endpoint_url);
                    }
                }));
            }
            for h in handles {
                h.join().unwrap();
            }
        });

        // Ten MAC addresses, so ten backend calls
        assert_eq!(
            api_server.calls_for(mock_api_server::ENDPOINT_DISCOVER_DHCP),
            10,
        );
    }

    fn multi_threading_test_inner(last_mac: u8, url: &str) {
        let builder_ffi = discovery_builder_allocate();
        unsafe {
            marshal_discovery_ffi(builder_ffi, |builder| {
                builder.relay_address([172, 20, 0, 13].into());
                builder.mac_address(MacAddress::new([2, 66, 172, 20, 13, last_mac]));
                builder.circuit_id("eth0");
                DiscoveryBuilderResult::Success
            });
        }
        let mut out = null_mut();
        let res = unsafe { discovery_fetch_machine_at(builder_ffi, &mut out, url) };
        assert_eq!(res, DiscoveryBuilderResult::Success);
        let machine = unsafe { &*out };
        assert!(mock_api_server::matches_mock_response(machine));
        unsafe {
            discovery_builder_free(builder_ffi);
        }
    }

    #[test]
    fn assert_thread_safety() {
        fn assert_send<T: Send>() {}
        assert_send::<Machine>();
        assert_send::<DiscoveryBuilderFFI>();
    }

    #[test]
    fn test_discovery_fetch_machine_success_after_failure() {
        // Start the mock API server.
        let rt: &tokio::runtime::Runtime = CarbideDhcpContext::get_tokio_runtime();
        let mut api_server = rt.block_on(mock_api_server::MockAPIServer::start());

        // Input packet, found by printing a real one
        let builder_ffi = discovery_builder_allocate();
        unsafe {
            marshal_discovery_ffi(builder_ffi, |builder| {
                builder.relay_address([172, 20, 0, 12].into());
                builder.mac_address(MacAddress::new([2, 66, 172, 20, 0, 12]));
                builder.circuit_id("eth0");
                DiscoveryBuilderResult::Success
            });
        }

        // Pointer to result will go here
        let mut out = null_mut();

        // Test after introducing a failure in the API.
        api_server.set_inject_failure(true);
        let res = unsafe {
            discovery_fetch_machine_at(builder_ffi, &mut out, api_server.local_http_addr())
        };
        assert_eq!(res, DiscoveryBuilderResult::FetchMachineError);

        // TODO: how can we check that there is a negative cache entry?

        // Check
        assert!(out.is_null());
        assert_eq!(
            api_server.calls_for(mock_api_server::ENDPOINT_DISCOVER_DHCP),
            1
        );

        // If we fix the API, and call again, the cache entry should be reset.
        api_server.set_inject_failure(false);
        let res = unsafe {
            discovery_fetch_machine_at(builder_ffi, &mut out, api_server.local_http_addr())
        };
        assert_eq!(res, DiscoveryBuilderResult::Success);

        // TODO: again it would be good to verify the CacheEntryStatus of the CacheEntry

        // Check
        let machine = unsafe { &*out };
        assert!(mock_api_server::matches_mock_response(machine));
        assert_eq!(
            api_server.calls_for(mock_api_server::ENDPOINT_DISCOVER_DHCP),
            2,
        );

        unsafe {
            discovery_builder_free(builder_ffi);
        }
    }

    #[test]
    fn test_discovery_fetch_machine_multi_failure() {
        // Start the mock API server.
        let rt: &tokio::runtime::Runtime = CarbideDhcpContext::get_tokio_runtime();
        let mut api_server = rt.block_on(mock_api_server::MockAPIServer::start());

        // Input packet, found by printing a real one
        let builder_ffi = discovery_builder_allocate();
        unsafe {
            marshal_discovery_ffi(builder_ffi, |builder| {
                builder.relay_address([172, 20, 0, 14].into());
                builder.mac_address(MacAddress::new([2, 66, 172, 20, 14, 42]));
                builder.circuit_id("eth0");
                DiscoveryBuilderResult::Success
            });
        }

        // Pointer to result will go here
        let mut out = null_mut();

        // Inject a failure to the API server, and test multiple discovery_fetch_machine_at calls.
        api_server.set_inject_failure(true);
        for attempt in 1..=cache::MAX_DISCOVERY_FAILS {
            let res = unsafe {
                discovery_fetch_machine_at(builder_ffi, &mut out, api_server.local_http_addr())
            };
            assert_eq!(res, DiscoveryBuilderResult::FetchMachineError);

            // Check
            assert!(out.is_null());
            assert_eq!(
                api_server.calls_for(mock_api_server::ENDPOINT_DISCOVER_DHCP),
                attempt as usize,
            );
        }

        // Now there should be no more calls to the API, since we've reached the max allowed number of fails.
        let res = unsafe {
            discovery_fetch_machine_at(builder_ffi, &mut out, api_server.local_http_addr())
        };
        assert_eq!(res, DiscoveryBuilderResult::TooManyFailuresError);

        // Check
        assert!(out.is_null());
        assert_eq!(
            api_server.calls_for(mock_api_server::ENDPOINT_DISCOVER_DHCP),
            cache::MAX_DISCOVERY_FAILS as usize,
        );

        // TODO: we should test that the cache entry is removed after 5 mins, but I don't want to add
        // a sleep for that long.

        unsafe {
            discovery_builder_free(builder_ffi);
        }
    }
}
