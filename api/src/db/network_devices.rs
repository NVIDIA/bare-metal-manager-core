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

use itertools::Itertools;
use sqlx::{Postgres, Transaction};

use super::{machine::DbMachineId, DatabaseError, ObjectFilter};
use crate::model::{
    hardware_info::LldpSwitchData,
    machine::machine_id::MachineId,
    network_devices::{
        DpuLocalPorts, DpuToNetworkDeviceMap, LldpError, NetworkDevice, NetworkTopologyData,
    },
};

pub struct NetworkDeviceSearchConfig {
    include_dpus: bool,
}

impl NetworkDeviceSearchConfig {
    pub fn new(include_dpus: bool) -> Self {
        NetworkDeviceSearchConfig { include_dpus }
    }
}

fn get_port_data<'a>(
    data: &'a [LldpSwitchData],
    port: &DpuLocalPorts,
) -> Result<&'a LldpSwitchData, LldpError> {
    let port_data = data
        .iter()
        .filter(|x| x.local_port == port.to_string())
        .collect::<Vec<&LldpSwitchData>>();

    let port_data = port_data
        .first()
        .ok_or(LldpError::MissingPort(port.to_string()))?;

    Ok(*port_data)
}

impl NetworkDevice {
    pub async fn find(
        txn: &mut Transaction<'_, Postgres>,
        filter: ObjectFilter<'_, &str>,
        search_config: &NetworkDeviceSearchConfig,
    ) -> Result<Vec<Self>, DatabaseError> {
        let base_query = "SELECT * FROM network_devices l {where}".to_owned();

        let mut devices = match filter {
            ObjectFilter::All => {
                sqlx::query_as::<_, NetworkDevice>(&base_query.replace("{where}", ""))
                    .fetch_all(&mut **txn)
                    .await
                    .map_err(|e| DatabaseError::new(file!(), line!(), "network_devices All", e))
            }
            ObjectFilter::One(id) => {
                let where_clause = "WHERE l.id=$1".to_string();
                sqlx::query_as::<_, NetworkDevice>(&base_query.replace("{where}", &where_clause))
                    .bind(id.to_string())
                    .fetch_all(&mut **txn)
                    .await
                    .map_err(|e| DatabaseError::new(file!(), line!(), "network_devices One", e))
            }
            ObjectFilter::List(list) => {
                let where_clause = "WHERE l.id=ANY($1)".to_string();
                let str_list: Vec<String> = list.iter().map(|id| id.to_string()).collect();
                sqlx::query_as::<_, NetworkDevice>(&base_query.replace("{where}", &where_clause))
                    .bind(str_list)
                    .fetch_all(&mut **txn)
                    .await
                    .map_err(|e| DatabaseError::new(file!(), line!(), "network_devices List", e))
            }
        }?;

        if search_config.include_dpus {
            for device in &mut devices {
                device.dpus =
                    DpuToNetworkDeviceMap::find_by_network_device_id(txn, device.id()).await?;
            }
        }

        Ok(devices)
    }

    async fn create(
        txn: &mut Transaction<'_, Postgres>,
        data: &LldpSwitchData,
    ) -> Result<Self, DatabaseError> {
        let query = "INSERT INTO network_devices(id, name, description, ip_addresses) VALUES($1, $2, $3, $4::inet[]) RETURNING *";

        sqlx::query_as(query)
            .bind(&data.id)
            .bind(&data.name)
            .bind(&data.description)
            .bind(&data.ip_address)
            .fetch_one(&mut **txn)
            .await
            .map_err(|e| DatabaseError::new(file!(), line!(), query, e))
    }

    pub async fn get_or_create_network_device(
        txn: &mut Transaction<'_, Postgres>,
        data: &LldpSwitchData,
    ) -> Result<NetworkDevice, LldpError> {
        let network_device = NetworkDevice::find(
            txn,
            ObjectFilter::One(&data.id),
            &NetworkDeviceSearchConfig::new(false),
        )
        .await
        .map_err(LldpError::from)?;

        if !network_device.is_empty() {
            return Ok(network_device[0].clone());
        }

        NetworkDevice::create(txn, data)
            .await
            .map_err(LldpError::from)
    }

    pub async fn lock_network_device_table(
        txn: &mut Transaction<'_, Postgres>,
    ) -> Result<(), DatabaseError> {
        let query = "LOCK TABLE network_device_lock IN EXCLUSIVE MODE";
        sqlx::query(query)
            .execute(&mut **txn)
            .await
            .map_err(|e| DatabaseError::new(file!(), line!(), query, e))?;
        Ok(())
    }

    /// This function should be called whenever a entry is updated/deleted in
    /// port_to_network_device_map table. Problem with update is that it can create extra load on
    /// db as there are very few chances of port update. So this function is called only from
    /// delete port_to_network_device_map call.
    pub async fn cleanup_unused_switches(
        txn: &mut Transaction<'_, Postgres>,
    ) -> Result<(), DatabaseError> {
        Self::lock_network_device_table(txn).await?;
        let query = "DELETE FROM network_devices WHERE id NOT IN (SELECT network_device_id FROM port_to_network_device_map) RETURNING *";

        let result = sqlx::query_as::<_, NetworkDevice>(query)
            .fetch_all(&mut **txn)
            .await
            .map_err(|e| DatabaseError::new(file!(), line!(), query, e))?;

        if !result.is_empty() {
            let ids = result.iter().map(|x| x.id()).join(",");
            tracing::info!(ids, "Network devices cleaned up as no attached DPU found.")
        }

        Ok(())
    }
}

impl DpuToNetworkDeviceMap {
    pub async fn create(
        txn: &mut Transaction<'_, Postgres>,
        local_port: &str,
        remote_port: &str,
        dpu_id: &MachineId,
        network_device_id: &str,
    ) -> Result<Self, DatabaseError> {
        // Update the association if already exists, else just insert into table.
        let query = r#"INSERT INTO port_to_network_device_map(dpu_id, local_port, remote_port, network_device_id)
                         VALUES($1, $2::dpu_local_ports, $3, $4)
                         ON CONFLICT ON CONSTRAINT network_device_dpu_associations_primary
                         DO UPDATE SET
                            network_device_id=EXCLUDED.network_device_id,
                            local_port=EXCLUDED.local_port,
                            remote_port=EXCLUDED.remote_port
                       RETURNING *"#;

        sqlx::query_as(query)
            .bind(dpu_id.to_string())
            .bind(local_port)
            .bind(remote_port)
            .bind(network_device_id)
            .fetch_one(&mut **txn)
            .await
            .map_err(|e| DatabaseError::new(file!(), line!(), query, e))
    }

    pub async fn delete(
        txn: &mut Transaction<'_, Postgres>,
        dpu_id: &MachineId,
    ) -> Result<(), DatabaseError> {
        // delete the association.
        let query = r#"DELETE from port_to_network_device_map WHERE dpu_id=$1 RETURNING dpu_id"#;

        let _ids = sqlx::query_as::<_, DbMachineId>(query)
            .bind(dpu_id.to_string())
            .fetch_all(&mut **txn)
            .await
            .map_err(|e| DatabaseError::new(file!(), line!(), query, e))?;

        NetworkDevice::cleanup_unused_switches(txn).await
    }

    pub async fn create_dpu_network_device_association(
        txn: &mut Transaction<'_, Postgres>,
        device_data: &[LldpSwitchData],
        dpu_id: &MachineId,
    ) -> Result<(), LldpError> {
        // It is possible that due to older dpu_agent, this data is null for now. In any case,
        // discovery functionality should not be broken.
        // TODO: This check should be removed after sometime.
        if device_data.is_empty() {
            tracing::warn!(machine_id=%dpu_id, "LLDP data is empty for DPU.");
            return Ok(());
        }

        NetworkDevice::lock_network_device_table(txn).await?;

        // Need to create 3 associations: oob_net0, p0 and p1
        for port in &[DpuLocalPorts::OobNet0, DpuLocalPorts::P0, DpuLocalPorts::P1] {
            // In case any port is missing, print error and continue to avoid discovery failure.
            match get_port_data(device_data, port) {
                Ok(data) => {
                    let tor = NetworkDevice::get_or_create_network_device(txn, data).await?;
                    Self::create(txn, &data.local_port, &data.remote_port, dpu_id, tor.id())
                        .await?;
                }
                Err(err) => {
                    tracing::warn!(%port, error=format!("{err:#}"), "LLDP data missing");
                }
            }
        }

        Ok(())
    }

    pub async fn find_by_network_device_id(
        txn: &mut Transaction<'_, Postgres>,
        device_id: &str,
    ) -> Result<Vec<Self>, DatabaseError> {
        let base_query = "SELECT * FROM port_to_network_device_map l WHERE network_device_id=$1";

        sqlx::query_as::<_, Self>(base_query)
            .bind(device_id)
            .fetch_all(&mut **txn)
            .await
            .map_err(|e| DatabaseError::new(file!(), line!(), "network_device_id", e))
    }

    pub async fn find_by_dpu_ids(
        txn: &mut Transaction<'_, Postgres>,
        dpu_ids: &[String],
    ) -> Result<Vec<Self>, DatabaseError> {
        let base_query = "SELECT * FROM port_to_network_device_map l WHERE dpu_id=ANY($1)";

        let str_list: Vec<String> = dpu_ids.iter().map(|id| id.to_string()).collect();
        sqlx::query_as::<_, DpuToNetworkDeviceMap>(base_query)
            .bind(str_list)
            .fetch_all(&mut **txn)
            .await
            .map_err(|e| DatabaseError::new(file!(), line!(), "port_to_network_device_map", e))
    }
}

impl NetworkTopologyData {
    pub async fn get_topology(
        txn: &mut Transaction<'_, Postgres>,
        filter: ObjectFilter<'_, &str>,
    ) -> Result<Self, LldpError> {
        Ok(NetworkTopologyData {
            network_devices: NetworkDevice::find(
                txn,
                filter,
                &NetworkDeviceSearchConfig::new(true),
            )
            .await?,
        })
    }
}
