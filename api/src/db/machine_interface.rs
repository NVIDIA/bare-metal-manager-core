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
use std::collections::HashMap;
use std::net::IpAddr;

use ipnetwork::IpNetwork;
use itertools::Itertools;
use mac_address::MacAddress;
use sqlx::{postgres::PgRow, Acquire, FromRow, Postgres, Row, Transaction};
use uuid::Uuid;

use ::rpc::forge as rpc;

use crate::db::address_selection_strategy::AddressSelectionStrategy;
use crate::db::machine::Machine;
use crate::db::machine_interface_address::MachineInterfaceAddress;
use crate::db::network_segment::NetworkSegment;
use crate::{db::network_segment::IpAllocationError, CarbideError, CarbideResult};

use super::UuidKeyedObjectFilter;

const SQL_VIOLATION_DUPLICATE_MAC: &str = "machine_interfaces_segment_id_mac_address_key";
const SQL_VIOLATION_ONE_PRIMARY_INTERFACE: &str = "one_primary_interface_per_machine";

#[derive(Debug, Clone)]
pub struct MachineInterface {
    pub id: uuid::Uuid,
    attached_dpu_machine_id: Option<uuid::Uuid>,
    domain_id: Option<uuid::Uuid>,
    pub machine_id: Option<uuid::Uuid>,
    segment_id: uuid::Uuid,
    pub mac_address: MacAddress,
    hostname: String,
    primary_interface: bool,
    addresses: Vec<MachineInterfaceAddress>,
}

/*
RON AND IAN Discussion Notes -
 2022-09-08T22:51:51.560Z INFO  carbide_api::api     > No existing machine with mac address 08:C0:EB:CB:0D:F4 using network with relay: 10.180.221.193, creating one.

 - a DPU comes up and is provisioned with an OOB IP address
 - a DPU gets assigned a kube VPC-resource-leaf ID and we store this in our database
 - We send Vpc "spec" to kubernetes and wait for Kube-vpc to provision DPU and assign a loopback IP
    -- we specifically store the loopback IP address that Kube allocates/provisions on our leaf resource.
 - a guest (referred to as x86 for brevity) comes up and does DHCP to get an IP address
    -- as part of the IP address allocation, the machine information is stored in our database
    -- at this point, we need to know the VPL ID of the DPU associated with this guest
    -- the loopback IP address of the DPU is located in the DHCP request (the gipaddr), and we need to map that to a VPL ID,
        so that we can update the leaf on Kube with the IP address we're handing out to the x86 guest.
    -- we can use this loopback IP to map back to the VPL ID, so that we can update the leaf with the new x86 host IP Address.
 - the machine, with its brand new x86 host IP address, boots via pxe over http.
 - if the machine is de-provisioned, the x86 IP address will need to be removed from both our database and Kube so that it
    can be handed back out to another machine.
*/
impl<'r> FromRow<'r, PgRow> for MachineInterface {
    fn from_row(row: &'r PgRow) -> Result<Self, sqlx::Error> {
        Ok(MachineInterface {
            id: row.try_get("id")?,
            attached_dpu_machine_id: row.try_get("attached_dpu_machine_id")?,
            machine_id: row.try_get("machine_id")?,
            segment_id: row.try_get("segment_id")?,
            domain_id: row.try_get("domain_id")?,
            hostname: row.try_get("hostname")?,
            mac_address: row.try_get("mac_address")?,
            primary_interface: row.try_get("primary_interface")?,
            addresses: Vec::new(),
        })
    }
}

impl From<MachineInterface> for rpc::MachineInterface {
    fn from(machine_interface: MachineInterface) -> rpc::MachineInterface {
        rpc::MachineInterface {
            id: Some(machine_interface.id.into()),
            attached_dpu_machine_id: machine_interface.attached_dpu_machine_id.map(|d| d.into()),
            machine_id: machine_interface.machine_id.map(|v| v.into()),
            segment_id: Some(machine_interface.segment_id.into()),
            hostname: machine_interface.hostname,
            domain_id: machine_interface.domain_id.map(|d| d.into()),
            mac_address: machine_interface.mac_address.to_string(),
            primary_interface: machine_interface.primary_interface,
            address: machine_interface
                .addresses
                .iter()
                .map(|addr| addr.address.to_string())
                .collect(),
        }
    }
}

impl MachineInterface {
    /// Update machine interface hostname
    ///
    /// This updates the machine_interfaces hostname which will render the old name in-accessible after the DNS
    /// TTL expires on recursive resolvers.  The authoritative resolver is updated immediately.
    ///
    /// Arguments:
    ///
    /// * `txn` - A reference to a currently open database transaction
    /// * `new_hostname` - The new hostname, which is subject to DNS validation rules (todo!())
    pub async fn update_hostname(
        &mut self,
        txn: &mut Transaction<'_, Postgres>,
        new_hostname: &str,
    ) -> CarbideResult<&MachineInterface> {
        let (hostname,) = sqlx::query_as(
            "UPDATE machine_interfaces SET hostname=$1 WHERE id=$2 RETURNING hostname",
        )
        .bind(new_hostname)
        .bind(self.id())
        .fetch_one(txn)
        .await?;

        self.hostname = hostname;

        Ok(self)
    }

    pub async fn associate_interface_with_dpu_machine(
        &mut self,
        txn: &mut Transaction<'_, Postgres>,
        vpc_leaf_id: &uuid::Uuid,
    ) -> CarbideResult<Self> {
        sqlx::query_as(
            "UPDATE machine_interfaces SET attached_dpu_machine_id=$1::uuid where id=$2::uuid RETURNING *",
        )
            .bind(vpc_leaf_id)
            .bind(self.id)
            .fetch_one(&mut *txn)
            .await
            .map_err(|err: sqlx::Error| {
                CarbideError::from(err)
            })
    }

    pub async fn associate_interface_with_machine(
        &mut self,
        txn: &mut Transaction<'_, Postgres>,
        machine_id: &uuid::Uuid,
    ) -> CarbideResult<Self> {
        sqlx::query_as(
            "UPDATE machine_interfaces SET machine_id=$1::uuid where id=$2::uuid RETURNING *",
        )
        .bind(machine_id)
        .bind(self.id)
        .fetch_one(&mut *txn)
        .await
        .map_err(|err: sqlx::Error| match err {
            sqlx::Error::Database(e)
                if e.constraint() == Some(SQL_VIOLATION_ONE_PRIMARY_INTERFACE) =>
            {
                CarbideError::OnePrimaryInterface
            }
            _ => CarbideError::from(err),
        })
    }

    /// Returns the UUID of the machine object
    pub fn id(&self) -> &uuid::Uuid {
        &self.id
    }

    pub fn addresses(&self) -> &Vec<MachineInterfaceAddress> {
        &self.addresses
    }

    pub fn attached_dpu_machine_id(&self) -> &Option<uuid::Uuid> {
        &self.attached_dpu_machine_id
    }

    pub async fn find_by_mac_address(
        txn: &mut Transaction<'_, Postgres>,
        macaddr: MacAddress,
    ) -> CarbideResult<Vec<MachineInterface>> {
        Ok(
            sqlx::query_as(
                "SELECT * FROM machine_interfaces mi WHERE mi.mac_address = $1::macaddr",
            )
            .bind(macaddr)
            .fetch_all(txn)
            .await?,
        )
    }

    pub async fn find_by_machine_ids(
        txn: &mut Transaction<'_, Postgres>,
        machine_ids: &[uuid::Uuid],
    ) -> CarbideResult<HashMap<uuid::Uuid, Vec<MachineInterface>>> {
        Ok(
            MachineInterface::find_by(txn, UuidKeyedObjectFilter::List(machine_ids), "machine_id")
                .await?
                .into_iter()
                .into_group_map_by(|interface| interface.machine_id.unwrap()),
        )
    }

    pub async fn find_by_segment_id(
        txn: &mut Transaction<'_, Postgres>,
        segment_id: &uuid::Uuid,
    ) -> CarbideResult<Vec<MachineInterface>> {
        Ok(
            sqlx::query_as("SELECT * FROM machine_interfaces WHERE segment_id = $1")
                .bind(segment_id)
                .fetch_all(txn)
                .await?,
        )
    }

    pub async fn find_one(
        txn: &mut Transaction<'_, Postgres>,
        interface_id: uuid::Uuid,
    ) -> CarbideResult<MachineInterface> {
        let mut interfaces =
            MachineInterface::find_by(txn, UuidKeyedObjectFilter::One(interface_id), "id").await?;
        match interfaces.len() {
            0 => Err(CarbideError::FindOneReturnedNoResultsError(interface_id)),
            1 => Ok(interfaces.remove(0)),
            _ => Err(CarbideError::FindOneReturnedManyResultsError(interface_id)),
        }
    }

    /// Do basic validating on existing macs and create the interface if it does not exist
    pub async fn validate_existing_mac_and_create(
        txn: &mut Transaction<'_, Postgres>,
        mac_address: MacAddress,
        relay: IpAddr,
    ) -> CarbideResult<Self> {
        let mut existing_mac = MachineInterface::find_by_mac_address(txn, mac_address).await?;
        match &existing_mac.len() {
            0 => {
                log::debug!(
                    "No existing mac address[{0}] exists yet, creating one.",
                    mac_address
                );
                match NetworkSegment::for_relay(txn, relay).await? {
                    None => Err(CarbideError::NoNetworkSegmentsForRelay(relay)),
                    Some(segment) => {
                        // actually create the interface
                        let v = MachineInterface::create(
                            txn,
                            &segment,
                            &mac_address,
                            segment.subdomain_id,
                            Machine::generate_hostname_from_uuid(&uuid::Uuid::new_v4()),
                            true,
                            AddressSelectionStrategy::Automatic,
                        )
                        .await?;
                        Ok(v)
                    }
                }
            }
            1 => {
                log::debug!("An existing mac address[{0}] exists yet, validating the relay and returning it.", mac_address);
                let mac = existing_mac.remove(0);
                // Ensure the relay segment exists before blindly giving the mac address back out
                match NetworkSegment::for_relay(txn, relay).await? {
                    None => Err(CarbideError::NoNetworkSegmentsForRelay(relay)),
                    Some(_) => Ok(mac),
                }
            }
            _ => {
                log::warn!(
                    "More than existing mac address ({0}) for network segment (relay ip: {1})",
                    &mac_address,
                    &relay
                );
                Err(CarbideError::NetworkSegmentDuplicateMacAddress(mac_address))
            }
        }
    }

    pub async fn allocate_addresses(
        txn: &mut Transaction<'_, Postgres>,
        segment: &NetworkSegment,
        addresses: AddressSelectionStrategy<'_>,
    ) -> CarbideResult<Vec<IpNetwork>> {
        match addresses {
            AddressSelectionStrategy::Automatic => {
                // DeadLock: if these tables needs to be locked anywhere else, follow the sequence to
                // avoid deadlock.
                sqlx::query("LOCK TABLE machine_interfaces IN ACCESS EXCLUSIVE MODE")
                    .execute(&mut *txn)
                    .await?;
                sqlx::query("LOCK TABLE instance_subnet_addresses IN ACCESS EXCLUSIVE MODE")
                    .execute(&mut *txn)
                    .await?;

                //
                // Get the next address for each prefix on this network segment.  Split the result
                // list into successes and failures.
                //
                let (success, failures) = segment.next_address(&mut *txn).await?.into_iter().fold(
                    (vec![], vec![]),
                    |(mut successes, mut failures), item| {
                        match item {
                            Ok(address) => successes.push(address),
                            Err(error) => failures.push(error),
                        };

                        (successes, failures)
                    },
                );

                //
                // If there's any failures, join the errors together and return it wrapped in a new
                // error type.
                //
                if !failures.is_empty() {
                    Err(CarbideError::NetworkSegmentsExhausted(
                        failures
                            .into_iter()
                            .map(|failure| match failure {
                                IpAllocationError::PrefixExhausted(prefix) => format!(
                                    "Prefix: {0} ({1}) has exhausted all address space",
                                    prefix.id, prefix.prefix
                                ),
                            })
                            .join(", "),
                    ))
                } else {
                    //
                    // Otherwise just return the list of allocated IPs
                    //
                    Ok(success.into_iter().map(IpNetwork::from).collect_vec())
                }
            }
            _ => Ok(vec![]),
        }
    }

    pub async fn create(
        txn: &mut Transaction<'_, Postgres>,
        segment: &NetworkSegment,
        macaddr: &MacAddress,
        domain_id: Option<uuid::Uuid>,
        hostname: String,
        primary_interface: bool,
        addresses: AddressSelectionStrategy<'_>,
    ) -> CarbideResult<Self> {
        // We're potentially about to insert a couple rows, so create a savepoint.
        let mut inner_txn = txn.begin().await?;

        // If either requested addresses are auto-generated, we lock the entire table.
        let allocated_addresses =
            Self::allocate_addresses(&mut inner_txn, segment, addresses).await?;

        let interface_id: (Uuid, ) = sqlx::query_as("INSERT INTO machine_interfaces (segment_id, mac_address, hostname, domain_id, primary_interface) VALUES ($1::uuid, $2::macaddr, $3::varchar, $4::uuid, $5::bool) RETURNING id")
            .bind(segment.id())
            .bind(macaddr)
            .bind(hostname)
            .bind(domain_id)
            .bind(primary_interface)
            .fetch_one(&mut *inner_txn).await
            .map_err(|err: sqlx::Error| {
                match err {
                    sqlx::Error::Database(e) if e.constraint() == Some(SQL_VIOLATION_DUPLICATE_MAC) => CarbideError::NetworkSegmentDuplicateMacAddress(*macaddr),
                    sqlx::Error::Database(e) if e.constraint() == Some(SQL_VIOLATION_ONE_PRIMARY_INTERFACE) => CarbideError::OnePrimaryInterface,
                    _ => CarbideError::from(err)
                }
            })?;

        for address in allocated_addresses {
            sqlx::query("INSERT INTO machine_interface_addresses (interface_id, address) VALUES ($1::uuid, $2::inet)")
                .bind(&interface_id.0)
                .bind(address)
                .fetch_all(&mut *inner_txn).await?;
        }

        inner_txn.commit().await?;

        Ok(
            MachineInterface::find_by(txn, UuidKeyedObjectFilter::One(interface_id.0), "id")
                .await?
                .remove(0),
        )
    }

    /// Get a reference to the machine interface's segment id.
    pub fn segment_id(&self) -> Uuid {
        self.segment_id
    }

    pub fn hostname(&self) -> &str {
        &self.hostname
    }

    pub fn primary_interface(&self) -> bool {
        self.primary_interface
    }

    async fn find_by<'a>(
        txn: &mut Transaction<'_, Postgres>,
        filter: UuidKeyedObjectFilter<'_>,
        column: &'a str,
    ) -> CarbideResult<Vec<MachineInterface>> {
        let base_query = "SELECT * FROM machine_interfaces mi {where}".to_owned();

        let mut interfaces = match filter {
            UuidKeyedObjectFilter::All => {
                sqlx::query_as::<_, MachineInterface>(&base_query.replace("{where}", ""))
                    .fetch_all(&mut *txn)
                    .await?
            }
            UuidKeyedObjectFilter::One(uuid) => {
                sqlx::query_as::<_, MachineInterface>(
                    &base_query
                        .replace("{where}", "WHERE mi.{column}=$1")
                        .replace("{column}", column),
                )
                .bind(uuid)
                .fetch_all(&mut *txn)
                .await?
            }
            UuidKeyedObjectFilter::List(list) => {
                sqlx::query_as::<_, MachineInterface>(
                    &base_query
                        .replace("{where}", "WHERE mi.{column}=ANY($1)")
                        .replace("{column}", column),
                )
                .bind(list)
                .fetch_all(&mut *txn)
                .await?
            }
        };

        let mut addresses_for_interfaces = MachineInterfaceAddress::find_for_interface(
            &mut *txn,
            UuidKeyedObjectFilter::List(
                interfaces
                    .iter()
                    .map(|interface| interface.id)
                    .collect::<Vec<Uuid>>()
                    .as_slice(),
            ),
        )
        .await?;

        interfaces.iter_mut().for_each(|interface| {
            if let Some(addresses) = addresses_for_interfaces.remove(&interface.id) {
                interface.addresses = addresses;
            } else {
                log::warn!("Interface {0} has no addresses", &interface.id);
            }
        });

        Ok(interfaces)
    }

    pub async fn get_machine_interface_primary(
        machine_id: uuid::Uuid,
        txn: &mut sqlx::Transaction<'_, Postgres>,
    ) -> CarbideResult<MachineInterface> {
        MachineInterface::find_by_machine_ids(txn, &[machine_id])
            .await?
            .remove(&machine_id)
            .ok_or(CarbideError::NotFoundError(machine_id))?
            .into_iter()
            .filter(|m_intf| m_intf.primary_interface())
            .collect::<Vec<MachineInterface>>()
            .pop()
            .ok_or_else(|| {
                CarbideError::GenericError(format!(
                    "Couldn't find primary interface for {}.",
                    machine_id
                ))
            })
    }
}
