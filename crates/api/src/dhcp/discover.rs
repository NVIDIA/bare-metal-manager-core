/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */
use std::net::{IpAddr, Ipv4Addr};
use std::str::FromStr;

use ::rpc::forge as rpc;
use carbide_uuid::machine::MachineId;
use carbide_uuid::rack::RackId;
use db::dhcp_entry::DhcpEntry;
use db::{self, expected_machine, machine_interface};
use mac_address::MacAddress;
use model::dpa_interface::DpaInterface;
use model::expected_machine::ExpectedHostNic;
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

    let mut dpa_ifs = db::dpa_interface::find_by_mac_addr(txn, &macaddr).await?;

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
    let mut host_nic: Option<ExpectedHostNic> = None;

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
                    let predicted_machine_id = expected_interface.machine_id;
                    machine_interface::move_predicted_machine_interface_to_machine(
                        &mut txn,
                        &expected_interface,
                        relay_ip,
                    )
                    .await?;
                    // replace predicted id saved above in rack table with actual id
                    update_rack_config_predicted_id_with_actual(
                        &mut txn,
                        &parsed_mac,
                        &predicted_machine_id,
                        &expected_interface.machine_id,
                    )
                    .await?;
                    Some(expected_interface.machine_id)
                } else {
                    if let Some(resp) = handle_dhcp_from_dpa(
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
                                for nic in m.data.host_nics {
                                    if nic.mac_address == parsed_mac {
                                        host_nic = Some(nic);
                                    }
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
    )
    .await?;

    if let Some(machine_id) = machine_interface.machine_id {
        // Can't block host's DHCP handling completely to support Zero-DPU.
        if machine_id.machine_type().is_host()
            && let Some(instance_id) =
                db::instance::find_id_by_machine_id(&mut txn, &machine_id).await?
        {
            // An instance is associated with machine id. DPU must process it.
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

    let record: rpc::DhcpRecord =
        db::dhcp_record::find_by_mac_address(&mut txn, &parsed_mac, &machine_interface.segment_id)
            .await?
            .into();

    txn.commit().await?;
    Ok(Response::new(record))
}

async fn update_rack_config_predicted_id_with_actual(
    txn: &mut PgConnection,
    parsed_mac: &MacAddress,
    predicted: &MachineId,
    actual: &MachineId,
) -> Result<(), CarbideError> {
    // TODO: pass in a rack id query by that when we support multirack, when supported
    let racks = db::rack::list(txn).await?;
    let rack = match racks.is_empty() {
        false => racks[0].clone(),
        true => {
            let expected_compute_trays = vec![*parsed_mac];
            #[allow(deprecated)]
            let rack_id: RackId = RackId::default();
            let rack = db::rack::create(txn, rack_id, expected_compute_trays, vec![], vec![])
                .await
                .map_err(CarbideError::from)?;
            tracing::warn!(
                "Handling DHCP response for mac {parsed_mac} but no rack was found! Create one with id {rack_id}"
            );
            rack
        }
    };

    let mut config = rack.config.clone();
    if let Some(item) = config
        .compute_trays
        .iter_mut()
        .find(|item| *item == predicted)
    {
        *item = *actual;
        db::rack::update(txn, rack.id, &config)
            .await
            .map_err(CarbideError::from)?;
    }
    Ok(())
}
