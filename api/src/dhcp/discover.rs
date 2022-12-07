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
use std::net::IpAddr;
use std::str::FromStr;
use std::time::{Duration, Instant};

use lru::LruCache;
use mac_address::MacAddress;
use tokio::sync::Mutex;
use tonic::{Request, Response, Status};

use crate::{
    db::{
        dhcp_entry::DhcpEntry,
        dhcp_record::{DhcpRecord, InstanceDhcpRecord},
        instance::Instance,
        machine::Machine,
        machine_interface::MachineInterface,
        network_segment::NetworkSegment,
        vpc_resource_leaf::VpcResourceLeaf,
    },
    dhcp::allocation::DhcpError,
    kubernetes, CarbideError,
};
pub use ::rpc::forge as rpc;

#[derive(Debug, Clone)]
pub struct RecordCacheEntry {
    pub record: rpc::DhcpRecord,
    pub timestamp: Instant,
    pub link_address: IpAddr,
    pub circuit_id: Option<String>,
}

pub async fn discover_dhcp(
    database_connection: &sqlx::PgPool,
    dhcp_discovery_cache: &Mutex<LruCache<MacAddress, RecordCacheEntry>>,
    request: Request<rpc::DhcpDiscovery>,
) -> Result<Response<rpc::DhcpRecord>, Status> {
    let mut txn = database_connection
        .begin()
        .await
        .map_err(CarbideError::from)?;

    let rpc::DhcpDiscovery {
        mac_address,
        relay_address,
        link_address,
        vendor_string,
        circuit_id,
        ..
    } = request.into_inner();

    // first, we detect that the link address is present or not, and use it  if it exists, and fall back to the relay address if not
    // we do this so that we can properly serve an address via DHCP because we can only serve address from "our" CIDR, and "our" CIDR is identified by the
    // link address, but the actual relay_address is necessary to look up leaf_ids
    let address_to_use_for_dhcp = link_address.as_ref().unwrap_or(&relay_address);
    let parsed_relay = address_to_use_for_dhcp
        .parse()
        .map_err(CarbideError::from)?;
    let relay_ip = IpAddr::from_str(&relay_address).map_err(CarbideError::from)?;

    let parsed_mac: MacAddress = mac_address
        .parse::<MacAddress>()
        .map_err(CarbideError::from)?;
    {
        let mut dhcp_discovery_cache = dhcp_discovery_cache.lock().await;
        if let Some(cache_entry) = dhcp_discovery_cache.get(&parsed_mac) {
            if cache_entry.timestamp.elapsed() < Duration::from_secs(60)
                && cache_entry.link_address == parsed_relay
                && cache_entry.circuit_id == circuit_id
            {
                log::info!("returning cached response for {parsed_mac:?}");
                let record_clone = cache_entry.record.clone();
                return Ok(Response::new(record_clone));
            } else {
                let _removed = dhcp_discovery_cache.pop_entry(&parsed_mac);
            }
        }
    }

    let existing_machines =
        Machine::find_existing_machines(&mut txn, parsed_mac, parsed_relay).await?;

    // Instance handling
    let possible_instance: Option<Instance> =
        Instance::find_by_relay_ip(&mut txn, relay_ip).await?;

    if let Some(instance) = possible_instance {
        let circuit_id_parsed = circuit_id
            .as_ref()
            .ok_or(DhcpError::MissingCircuitId(instance.id))
            .map_err(CarbideError::from)?;
        let record: rpc::DhcpRecord = InstanceDhcpRecord::find_for_instance(
            &mut txn,
            parsed_mac,
            circuit_id_parsed.clone(),
            instance.clone(),
        )
        .await
        .map_err(|x| {
            log::error!(
                "DHCP request failed for {}, {:?} with {}.",
                instance.id,
                circuit_id,
                x
            );
            CarbideError::from(DhcpError::InvalidInterface(
                instance.id,
                circuit_id_parsed.clone(),
            ))
        })?
        .try_into()?;
        txn.commit().await.map_err(CarbideError::from)?;

        log::info!(
            "Returning DHCP response for instance {}, circuit_id: {}, record: {:?}",
            instance.id,
            circuit_id_parsed,
            record
        );

        dhcp_discovery_cache.lock().await.put(
            parsed_mac,
            RecordCacheEntry {
                record: record.clone(),
                timestamp: Instant::now(),
                link_address: parsed_relay,
                circuit_id,
            },
        );

        return Ok(Response::new(record));
    }

    let newly_created_interface;
    let mut machine_interface = match &existing_machines.len() {
        0 => {
            newly_created_interface = true;
            log::info!("No existing machine with mac address {} using network with relay: {}, creating one.", parsed_mac, parsed_relay);
            MachineInterface::validate_existing_mac_and_create(&mut txn, parsed_mac, parsed_relay)
                .await
        }
        1 => {
            newly_created_interface = false;
            let mut ifcs = MachineInterface::find_by_mac_address(&mut txn, parsed_mac).await?;
            match ifcs.len() {
                1 => Ok(ifcs.remove(0)),
                n => {
                    log::warn!(
                        "{0} existing mac address ({1}) for network segment (relay ip: {2})",
                        n,
                        &mac_address,
                        &address_to_use_for_dhcp
                    );
                    Err(CarbideError::NetworkSegmentDuplicateMacAddress(parsed_mac))
                }
            }
        }
        _ => {
            newly_created_interface = false;
            log::warn!(
                    "More than machine found with mac address ({0}) for network segment (relay ip: {1})",
                    &mac_address, &address_to_use_for_dhcp
                );
            Err(CarbideError::NetworkSegmentDuplicateMacAddress(parsed_mac))
        }
    }?;

    // Save vendor string, this is allowed to fail due to dhcp happening more than once on the same machine/vendor string
    if let Some(vendor) = vendor_string {
        let res = DhcpEntry {
            machine_interface_id: *machine_interface.id(),
            vendor_class: vendor,
        }
        .persist(&mut txn)
        .await;
        match res {
            Ok(_) => {} // do nothing on ok result
            Err(e) => {
                log::debug!("Could not persist dhcp entry {}", e)
            } // This should not fail the discover call, dhcp happens many times
        }
    }

    txn.commit().await.map_err(CarbideError::from)?;

    let mut txn = database_connection
        .begin()
        .await
        .map_err(CarbideError::from)?;

    // There is some small bit of duplicated logic in the existing machines lookup and this.
    // A lookup for the machine interface is done above and could be combined with this if there
    // is a speed issue to overcome.
    let response = match NetworkSegment::for_relay(&mut txn, parsed_relay).await? {
        None => Err(CarbideError::NoNetworkSegmentsForRelay(parsed_relay).into()),
        Some(network) => Ok(Response::new({
            let record: rpc::DhcpRecord =
                DhcpRecord::find_by_mac_address(&mut txn, &parsed_mac, network.id())
                    .await?
                    .into();

            if newly_created_interface {
                let resource = VpcResourceLeaf::find_by_loopback_ip(&mut txn, relay_ip).await?;

                // we're using the presence of the mapping as a "tell" for whether this ia DPU -- we literally
                // fail provisioning of a leaf if it doesn't have this loopback assigned, precisely so that we
                // can create this mapping.  The only way for it to not be present for a given relay address is
                // if this is a DPU coming up for the very first time. In this case we need to do nothing -- because
                // the provisioning step in 'discover_machine' is going to create this mapping for us.
                if let Some(resource_leaf) = resource {
                    // we need to go look at our mapping and get the assigned leaf ID for this relay address
                    //TODO: think about making a GET leaf call in VPC resource actions
                    kubernetes::update_leaf(&mut txn, resource_leaf, record.clone()).await?;

                    let dpu_machine_interface =
                        VpcResourceLeaf::find_associated_dpu_machine_interface(&mut txn, relay_ip)
                            .await?;

                    if let Some(machine_id) = dpu_machine_interface.machine_id {
                        machine_interface
                            .associate_interface_with_dpu_machine(&mut txn, &machine_id)
                            .await?;
                    } else {
                        log::error!(
                            "Could not associate dpu with x86: {}, {}",
                            dpu_machine_interface.id(),
                            relay_address
                        )
                    }
                } else {
                    log::info!(
                            "VpcResourceLeaf not found, using relay ip: {} assuming this is DPU DHCPDISCOVER",
                            relay_address
                        )
                }
            }
            let record_clone = record.clone();
            dhcp_discovery_cache.lock().await.put(
                parsed_mac,
                RecordCacheEntry {
                    record: record_clone,
                    timestamp: Instant::now(),
                    link_address: parsed_relay,
                    circuit_id: None,
                },
            );
            record
        })),
    };

    txn.commit().await.map_err(CarbideError::from)?;
    response
}
