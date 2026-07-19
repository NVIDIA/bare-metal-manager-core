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
//! Helpers for running boot-interface-targeted Redfish operations with a
//! MAC-first / interface-id-fallback strategy.

use std::future::Future;

use ::libredfish::{BootInterfaceRef, RedfishError};
use mac_address::MacAddress;
use model::machine_boot_interface::MachineBootInterface;

/// How to target a host's boot interface for a Redfish setup operation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BootInterfaceTarget {
    /// A fully-captured boot interface (MAC + Redfish interface id). The MAC is
    /// tried first; on failure the [stable] interface id is used as a fallback
    /// (see [`with_boot_interface_fallback`]). Carrying both keeps the boot
    /// interface addressable even when the MAC is no longer resolvable in
    /// Redfish.
    Pair(MachineBootInterface),
    /// Only a MAC is known -- the boot interface has never been captured with an
    /// interface id (e.g. a host last explored before id capture, or never
    /// reported with a resolvable interface id). No id fallback is possible.
    MacOnly(MacAddress),
}

impl BootInterfaceTarget {
    /// Runs `op` against this boot interface. For [`BootInterfaceTarget::Pair`]
    /// the MAC is tried first and the interface id is used as a fallback; for
    /// [`BootInterfaceTarget::MacOnly`] only the MAC is attempted.
    ///
    /// `op` is invoked with a [`BootInterfaceRef`] and should call the desired
    /// Redfish trait method with it, e.g.
    /// `|bi| client.set_boot_order_dpu_first(bi)` or
    /// `|bi| client.is_bios_setup(Some(bi))`.
    pub async fn run<'s, T, F, Fut>(&'s self, op: F) -> Result<T, RedfishError>
    where
        F: Fn(BootInterfaceRef<'s>) -> Fut,
        Fut: Future<Output = Result<T, RedfishError>>,
    {
        match self {
            BootInterfaceTarget::Pair(boot_interface) => {
                with_boot_interface_fallback(
                    boot_interface.mac_address,
                    &boot_interface.interface_id,
                    op,
                )
                .await
            }
            BootInterfaceTarget::MacOnly(mac) => op(BootInterfaceRef::Mac(*mac)).await,
        }
    }

    /// The MAC of this boot interface (always present for both variants).
    pub fn mac_address(&self) -> MacAddress {
        match self {
            BootInterfaceTarget::Pair(boot_interface) => boot_interface.mac_address,
            BootInterfaceTarget::MacOnly(mac) => *mac,
        }
    }
}

/// Runs a Redfish operation that targets a host's boot interface, trying the
/// MAC first and falling back to the [stable] vendor-native Redfish interface
/// id if the MAC attempt fails.
///
/// `op` is invoked with a [`BootInterfaceRef`] and should call the desired
/// Redfish trait method with it (e.g. `|bi| client.set_boot_order_dpu_first(bi)`
/// or `|bi| client.is_bios_setup(Some(bi))`).
///
/// The fallback is deliberately *not* gated on a specific error variant: a MAC
/// that can no longer be mapped to an interface surfaces as a vendor-specific /
/// generic Redfish error (e.g. Dell's "could not find network device function
/// for ..."), so pattern-matching it would be brittle across vendors. Retrying
/// with the interface id is safe -- the MAC lookup fails before any mutation --
/// and the id is the canonical Redfish-standard resolver
/// (`Systems/{}/EthernetInterfaces/{id}`), so it is also the attempt most likely
/// to succeed. In particular it covers the case where the MAC has dropped out of
/// Redfish entirely (e.g. after a BlueField operating-mode flip from DPU to NIC),
/// where the MAC-keyed calls can no longer locate the interface.
pub async fn with_boot_interface_fallback<'a, T, F, Fut>(
    mac_address: MacAddress,
    interface_id: &'a str,
    op: F,
) -> Result<T, RedfishError>
where
    F: Fn(BootInterfaceRef<'a>) -> Fut,
    Fut: Future<Output = Result<T, RedfishError>>,
{
    match op(BootInterfaceRef::Mac(mac_address)).await {
        Ok(value) => Ok(value),
        Err(mac_error) => {
            tracing::warn!(
                error = %mac_error,
                %interface_id,
                "boot-interface Redfish operation failed targeting the MAC; retrying by interface id"
            );
            op(BootInterfaceRef::InterfaceId(interface_id)).await
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;

    fn mac() -> MacAddress {
        MacAddress::new([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x01])
    }

    #[tokio::test]
    async fn fallback_retries_by_interface_id_when_mac_fails() {
        let attempts = AtomicUsize::new(0);
        let result: Result<&str, RedfishError> =
            with_boot_interface_fallback(mac(), "NIC.Slot.7-1-1", |bi| {
                attempts.fetch_add(1, Ordering::SeqCst);
                async move {
                    match bi {
                        // Simulate a MAC that no longer resolves to an interface.
                        BootInterfaceRef::Mac(_) => Err(RedfishError::NoContent),
                        BootInterfaceRef::InterfaceId(id) => {
                            assert_eq!(id, "NIC.Slot.7-1-1");
                            Ok("recovered")
                        }
                    }
                }
            })
            .await;

        assert_eq!(result.unwrap(), "recovered");
        assert_eq!(
            attempts.load(Ordering::SeqCst),
            2,
            "should try the MAC first, then fall back to the interface id"
        );
    }

    #[tokio::test]
    async fn fallback_does_not_retry_when_mac_succeeds() {
        let attempts = AtomicUsize::new(0);
        let result: Result<&str, RedfishError> =
            with_boot_interface_fallback(mac(), "NIC.Slot.7-1-1", |bi| {
                attempts.fetch_add(1, Ordering::SeqCst);
                async move {
                    assert!(matches!(bi, BootInterfaceRef::Mac(_)));
                    Ok("ok")
                }
            })
            .await;

        assert_eq!(result.unwrap(), "ok");
        assert_eq!(attempts.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn pair_target_runs_with_fallback() {
        let target = BootInterfaceTarget::Pair(MachineBootInterface {
            mac_address: mac(),
            interface_id: "NIC.Slot.7-1-1".to_string(),
        });
        let result: Result<bool, RedfishError> = target
            .run(|bi| async move {
                match bi {
                    BootInterfaceRef::Mac(_) => Err(RedfishError::NoContent),
                    BootInterfaceRef::InterfaceId(_) => Ok(true),
                }
            })
            .await;
        assert!(result.unwrap());
    }

    #[tokio::test]
    async fn mac_only_target_never_uses_interface_id() {
        let target = BootInterfaceTarget::MacOnly(mac());
        let result: Result<(), RedfishError> = target
            .run(|bi| async move {
                assert!(matches!(bi, BootInterfaceRef::Mac(_)));
                Ok(())
            })
            .await;
        assert!(result.is_ok());
    }
}
