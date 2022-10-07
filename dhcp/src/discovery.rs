/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2022 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */
use std::ffi::{c_char, CStr};
use std::net::Ipv4Addr;
use std::primitive::u32;

use derive_builder::Builder;
use mac_address::MacAddress;

use crate::machine::Machine;

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
}

#[no_mangle]
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
        }
        .as_bytes(),
    )
    .unwrap_or_default()
    .as_ptr()
}

#[derive(Debug, Builder)]
pub struct Discovery {
    pub(crate) relay_address: Ipv4Addr,
    pub(crate) mac_address: MacAddress,

    #[builder(setter(into, strip_option, name = "client_system"), default)]
    pub(crate) _client_system: Option<u16>,

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
/// The returned object must either be consumed by calling
/// `discovery_fetch_machine`, or freed by calling `discovery_builder_free`.
#[no_mangle]
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
    if builder.is_null() {
        return DiscoveryBuilderResult::InvalidDiscoveryBuilderPointer;
    }

    let builder = &mut *(builder as *mut DiscoveryBuilder);
    f(builder)
}

/// Fill the `client_system` portion of the discovery object
///
/// # Safety
///
/// This function is only safe to be called on a `ctx` which is either a null pointer
/// or a valid `DiscoveryBuilderFFI` object.
///
#[no_mangle]
pub unsafe extern "C" fn discovery_set_client_system(
    ctx: *mut DiscoveryBuilderFFI,
    client_system: u16,
) -> DiscoveryBuilderResult {
    marshal_discovery_ffi(ctx, |builder| {
        builder.client_system(client_system);
        DiscoveryBuilderResult::Success
    })
}

/// Fill the `vendor_class` portion of the discovery object
///
/// # Safety
///
/// This function is only safe to be called on a `ctx` which is either a null pointer
/// or a valid `DiscoveryBuilderFFI` object.
///
#[no_mangle]
pub unsafe extern "C" fn discovery_set_vendor_class(
    ctx: *mut DiscoveryBuilderFFI,
    vendor_class: *const libc::c_char,
) -> DiscoveryBuilderResult {
    let vendor_class = match CStr::from_ptr(vendor_class).to_str() {
        Ok(string) => string.to_owned(),
        Err(error) => {
            log::error!("Invalid UTF-8 byte string for vendor_class: {}", error);
            return DiscoveryBuilderResult::InvalidVendorClass;
        }
    };

    marshal_discovery_ffi(ctx, |builder| {
        builder.vendor_class(vendor_class);
        DiscoveryBuilderResult::Success
    })
}

/// Fill the `link select` portion of the Discovery object with an IP(v4) address
///
/// # Safety
///
/// This function is only safe to be called on a `ctx` which is either a null pointer
/// or a valid `DiscoveryBuilderFFI` object.
///
#[no_mangle]
pub unsafe extern "C" fn discovery_set_link_select(
    ctx: *mut DiscoveryBuilderFFI,
    link_select: u32,
) -> DiscoveryBuilderResult {
    marshal_discovery_ffi(ctx, |builder| {
        builder.link_select_address(Ipv4Addr::from(link_select.to_be_bytes()));
        DiscoveryBuilderResult::Success
    })
}

/// Fill the `relay` portion of the Discovery object with an IP(v4) address
///
/// # Safety
///
/// This function is only safe to be called on a `ctx` which is either a null pointer
/// or a valid `DiscoveryBuilderFFI` object.
///
#[no_mangle]
pub unsafe extern "C" fn discovery_set_relay(
    ctx: *mut DiscoveryBuilderFFI,
    relay: u32,
) -> DiscoveryBuilderResult {
    marshal_discovery_ffi(ctx, |builder| {
        builder.relay_address(Ipv4Addr::from(relay.to_be_bytes()));
        DiscoveryBuilderResult::Success
    })
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
#[no_mangle]
pub unsafe extern "C" fn discovery_set_mac_address(
    ctx: *mut DiscoveryBuilderFFI,
    mac_address_ptr: *const u8,
    mac_address_len: usize,
) -> DiscoveryBuilderResult {
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

/// Utilizes the DiscoveryBuilder to fetch a machine
///
/// If the method returns `DiscoveryBuilderResult::Success`, then the pointer
/// for a `Machine` handle will be written to `machine_ptr`. `machine_ptr` is an
/// output parameter for a `Machine` pointer.
///
/// This function is only safe to be called on a `ctx` which is either a null pointer
/// or a valid `DiscoveryBuilderFFI` object.
#[no_mangle]
pub unsafe extern "C" fn discovery_fetch_machine(
    ctx: *mut DiscoveryBuilderFFI,
    machine_ptr_out: *mut *mut Machine,
) -> DiscoveryBuilderResult {
    if machine_ptr_out.is_null() {
        return DiscoveryBuilderResult::InvalidMachinePointer;
    }
    *machine_ptr_out = std::ptr::null_mut();

    marshal_discovery_ffi(ctx, |builder| {
        let discovery = match builder.build() {
            Ok(discovery) => discovery,
            Err(err) => {
                log::info!("Error compiling the discovery builder object: {}", err);
                return DiscoveryBuilderResult::BuilderError;
            }
        };

        let r = discovery.relay_address;
        let m = discovery.mac_address;
        let v = match discovery.vendor_class.clone() {
            Some(s) => s,
            None => "No vendor specified in the request".to_string(),
        };

        match Machine::try_from(discovery) {
            Ok(machine) => {
                *machine_ptr_out = Box::into_raw(Box::new(machine));
                DiscoveryBuilderResult::Success
            }
            Err(e_str) => {
                log::info!(
                    "Error getting info back from the machine discovery: {}:{}:{}:{}",
                    m,
                    r,
                    v,
                    e_str
                );
                DiscoveryBuilderResult::FetchMachineError
            }
        }
    })
}

/// Free the Discovery Builder object.
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
pub unsafe extern "C" fn discovery_builder_free(ctx: *mut DiscoveryBuilderFFI) {
    drop(Box::from_raw(ctx as *mut DiscoveryBuilder));
}
