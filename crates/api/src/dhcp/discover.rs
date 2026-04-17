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
use std::net::{IpAddr, Ipv4Addr};
use std::str::FromStr;

use ::rpc::forge as rpc;
use carbide_network::ip::{IdentifyAddressFamily, IpAddressFamily};
use db::dhcp_entry::DhcpEntry;
use db::{self, expected_machine, machine_interface};
use mac_address::MacAddress;
use model::dpa_interface::DpaInterface;
use model::expected_machine::ExpectedHostNic;
use model::network_segment::AllocationStrategy;
use sqlx::PgConnection;
use tonic::{Request, Response};

use crate::CarbideError;
use crate::api::Api;

// MTU for both the underlay and overlay networks on
// the E/W Fabric
const SPX_MTU: i32 = 9000;

/// Given a desired IP address, compute the relay address by toggling the LSB.
fn get_relay_from_desired(desired: Ipv4Addr) -> Ipv4Addr {
    let ip_u32 = u32::from(desired);
    let relay_u32 = ip_u32 ^ 1;
    Ipv4Addr::from(relay_u32)
}

// Overlay IP address request from DPA. DPA tells us
// what IP address it wants (calculated algorithmically
// from the underlay IP address). So we just allocate
// that desired address and update the DB.
async fn handle_overlay_from_dpa(
    txn: &mut PgConnection,
    dpa_if: &mut DpaInterface,
    macaddr: MacAddress,
    desired_addr: IpAddr,
) -> Result<Option<Response<rpc::DhcpRecord>>, CarbideError> {
    let IpAddr::V4(ip_v4_addr) = desired_addr else {
        return Err(CarbideError::internal(
            "IPv6 not supported for DPA overlay".to_string(),
        ));
    };

    let relay_addr = get_relay_from_desired(ip_v4_addr);

    let prefix = format!("{relay_addr}/31");

    dpa_if.overlay_ip = Some(desired_addr);

    db::dpa_interface::update_ip(dpa_if.clone(), false, txn).await?;

    Ok(Some(Response::new(rpc::DhcpRecord {
        machine_id: Some(dpa_if.get_machine_id()),
        machine_interface_id: None,
        segment_id: None,
        subdomain_id: None,
        address: desired_addr.to_string(),
        mac_address: macaddr.to_string(),
        booturl: None,
        last_invalidation_time: None,
        gateway: Some(relay_addr.to_string()),
        mtu: SPX_MTU,
        fqdn: String::new(),
        prefix,
    })))
}

// DPA is asking for an underlay IP address. The underlay IP
// address is just the relay address with the LSB toggled.
async fn handle_underlay_from_dpa(
    txn: &mut PgConnection,
    dpa_if: &mut DpaInterface,
    macaddr: MacAddress,
    relay_address: String,
) -> Result<Option<Response<rpc::DhcpRecord>>, CarbideError> {
    // The relay address and the mac address should differ only in bit 0
    let relay_addr = Ipv4Addr::from_str(&relay_address)?;

    let ip_u32 = u32::from(relay_addr);

    let retaddr = ip_u32 ^ 1;

    let ret_addr = Ipv4Addr::from(retaddr);

    let prefix = format!("{relay_addr}/31");

    dpa_if.underlay_ip = Some(IpAddr::from(ret_addr));

    db::dpa_interface::update_ip(dpa_if.clone(), true, txn).await?;

    Ok(Some(Response::new(rpc::DhcpRecord {
        machine_id: Some(dpa_if.get_machine_id()),
        machine_interface_id: None,
        segment_id: None,
        subdomain_id: None,
        address: ret_addr.to_string(),
        mac_address: macaddr.to_string(),
        booturl: None,
        last_invalidation_time: None,
        gateway: Some(relay_address),
        mtu: SPX_MTU,
        fqdn: String::new(),
        prefix,
    })))
}

// See if this is a underlay/overlay IP allocation request
// from a DPA. If the specified macaddr belongs to any DPA
// object, we know it's a request from a DPA. And the presence
// of desired ip (option 50) means it's overlay request, and
// the absence of option 50 means it's an underlay request.
async fn handle_dhcp_from_dpa(
    api: &Api,
    txn: &mut PgConnection,
    macaddr: MacAddress,
    relay_address: String,
    desired_address: Option<IpAddr>,
) -> Result<Option<Response<rpc::DhcpRecord>>, CarbideError> {
    if !api.runtime_config.is_dpa_enabled() {
        return Ok(None);
    }

    let mut dpa_ifs = db::dpa_interface::find_by_mac_addr(&mut *txn, &macaddr).await?;

    if dpa_ifs.len() != 1 {
        // If the MAC address does not belong to any DPA object, len will be 0.
        // Log cases where len is neither 0 nor 1.
        if !dpa_ifs.is_empty() {
            tracing::error!(
                "handle_dpa_message -  invalid dpa_ifs len from find_by_mac_addr maddr: {} len: {}",
                macaddr,
                dpa_ifs.len()
            );
        }
        return Ok(None);
    }

    let mut dpa_if = dpa_ifs.remove(0);

    if let Some(addr) = desired_address {
        return handle_overlay_from_dpa(txn, &mut dpa_if, macaddr, addr).await;
    }

    handle_underlay_from_dpa(txn, &mut dpa_if, macaddr, relay_address).await
}

pub async fn discover_dhcp(
    api: &Api,
    request: Request<rpc::DhcpDiscovery>,
    rack_level_service: Option<bool>,
) -> Result<Response<rpc::DhcpRecord>, CarbideError> {
    let mut txn = api.txn_begin().await?;

    let rpc::DhcpDiscovery {
        mac_address,
        relay_address,
        link_address,
        vendor_string,
        desired_address,
        ..
    } = request.into_inner();

    // Use link address if present, else relay address. Link address represents subnet address at
    // first router.
    let address_to_use_for_dhcp = link_address.as_ref().unwrap_or(&relay_address);
    let parsed_relay = address_to_use_for_dhcp.parse()?;
    let relay_ip = IpAddr::from_str(&relay_address)?;
    let address_family = relay_ip.address_family();
    let mut host_nic: Option<ExpectedHostNic> = None;
    // `is_primary_nic` reflects the matched ExpectedHostNic's `primary` flag.
    // - `Some(true)` -- the operator flagged this NIC as the host's boot interface.
    // - `Some(false)` -- another NIC on this host is the declared primary.
    // - `None` -- no declaration, use the default at interface creation time.
    let mut is_primary_nic: Option<bool> = None;

    let parsed_mac: MacAddress = mac_address.parse()?;

    let desired_address_ip: Option<IpAddr> =
        desired_address.map(|addr| addr.parse()).transpose()?;

    let existing_machine_id =
        match db::machine::find_existing_machine(&mut txn, parsed_mac, parsed_relay).await? {
            Some(existing_machine) => Some(existing_machine),
            None => {
                if let Some(expected_interface) =
                    db::predicted_machine_interface::find_by_mac_address(&mut txn, parsed_mac)
                        .await?
                {
                    // remember expected machine id for later rack update
                    machine_interface::move_predicted_machine_interface_to_machine(
                        &mut txn,
                        &expected_interface,
                        relay_ip,
                    )
                    .await?;
                    Some(expected_interface.machine_id)
                } else {
                    // DPA allocation is currently IPv4-only. The overlay
                    // uses u32 arithmetic (LSB toggle) and /31 linknets,
                    // and the underlay parses relay_address as Ipv4Addr.
                    // Skip the DPA path entirely for IPv6 relays.
                    if address_family == IpAddressFamily::Ipv4
                        && let Some(resp) = handle_dhcp_from_dpa(
                            api,
                            &mut txn,
                            parsed_mac,
                            relay_address,
                            desired_address_ip,
                        )
                        .await?
                    {
                        txn.commit().await?;
                        return Ok(resp);
                    }

                    if let Some(x) = rack_level_service {
                        // check expected machines. all mac addresses we should respond to should be
                        // added in there for unknown machines that have not been discovered yet.
                        // TODO: fix for dpu with VF nics, they will currently not get IPs
                        if x {
                            let expected_machine =
                                expected_machine::find_by_host_mac_address(&mut txn, parsed_mac)
                                    .await
                                    .map_err(CarbideError::from)?;
                            if let Some(m) = expected_machine {
                                // select ip segment from Underlay for BMC, Admin for BF3/Onboard
                                for nic in &m.data.host_nics {
                                    if nic.mac_address == parsed_mac {
                                        host_nic = Some(nic.clone());
                                    }
                                }
                                // If any NIC on this host declares primary=true,
                                // then this NIC is primary iff it's that one.
                                // Handler-side validation keeps at most one
                                // primary=true per ExpectedMachine.
                                if let Some(declared_primary) =
                                    m.data.host_nics.iter().find(|n| n.primary == Some(true))
                                {
                                    is_primary_nic =
                                        Some(declared_primary.mac_address == parsed_mac);
                                }
                            }
                        }
                    }
                    None
                }
            }
        };

    let machine_interface = db::machine_interface::find_or_create_machine_interface(
        &mut txn,
        existing_machine_id,
        parsed_mac,
        parsed_relay,
        host_nic,
        is_primary_nic,
    )
    .await?;

    // If the interface has no address for the requested address family
    // (e.g., after a lease expiration cleaned up the DHCP allocation,
    // or this is a new address family for a dual-stack interface),
    // re-allocate from the segment.
    if !db::machine_interface_address::has_address_for_family(
        &mut txn,
        machine_interface.id,
        address_family,
    )
    .await?
    {
        tracing::info!(
            interface_id = %machine_interface.id,
            %parsed_mac,
            ?address_family,
            "Interface missing address for family, re-allocating from segment"
        );
        let segment = db::network_segment::for_relay(&mut txn, parsed_relay)
            .await?
            .ok_or_else(|| {
                CarbideError::internal(format!(
                    "No network segment defined for relay address: {parsed_relay}"
                ))
            })?;

        // If the segment only allows static reservations, don't
        // dynamically allocate. The device has no reservation.
        if segment.allocation_strategy == AllocationStrategy::Reserved {
            return Err(CarbideError::internal(format!(
                "segment {} configured for static DHCP leases only; no static reservation for MAC {parsed_mac}",
                segment.name,
            )));
        }

        db::machine_interface::allocate_address_for_family(
            &mut txn,
            machine_interface.id,
            &segment,
            address_family,
        )
        .await?;
    }

    if let Some(machine_id) = machine_interface.machine_id
        && machine_id.machine_type().is_host()
        && let Some(instance_id) =
            db::instance::find_id_by_machine_id(&mut txn, &machine_id).await?
    {
        // An instance is associated with this host. If the host has DPUs,
        // the DPUs proxy DHCP on its behalf, so we reject the host's direct
        // DHCP request. Zero-DPU hosts have no such intermediary, so let
        // their DHCP proceed.
        let dpus = db::machine::find_dpus_by_host_machine_id(&mut txn, &machine_id).await?;
        if !dpus.is_empty() {
            return Err(CarbideError::internal(format!(
                "DHCP request received for instance: {instance_id}. Ignoring."
            )));
        }
    }

    // Save vendor string, this is allowed to fail due to dhcp happening more than once on the same machine/vendor string
    if let Some(vendor) = vendor_string {
        let res = db::dhcp_entry::persist(
            DhcpEntry {
                machine_interface_id: machine_interface.id,
                vendor_string: vendor,
            },
            &mut txn,
        )
        .await;
        match res {
            Ok(()) => {} // do nothing on ok result
            Err(error) => {
                tracing::error!(%error, "Could not persist dhcp entry")
            } // This should not fail the discover call, dhcp happens many times
        }
    }

    db::machine_interface::update_last_dhcp(&mut txn, machine_interface.id, None).await?;

    txn.commit().await?;

    let mut txn = api.txn_begin().await?;

    let record: rpc::DhcpRecord = db::dhcp_record::find_by_mac_address(
        &mut txn,
        &parsed_mac,
        &machine_interface.segment_id,
        address_family,
    )
    .await?
    .into();

    txn.commit().await?;
    Ok(Response::new(record))
}
