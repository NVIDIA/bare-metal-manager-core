/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */

use async_trait::async_trait;
use carbide::model::machine::MachineSnapshot;
use carbide::redfish::{RedfishAuth, RedfishClientCreationError, RedfishClientPool};
use http::HeaderName;
use libredfish::{Endpoint, Redfish};
use machine_a_tron::host_machine::HostMachine;
use std::net::{IpAddr, SocketAddr};
use std::{net::Ipv4Addr, str::FromStr, sync::Arc};
use tokio::sync::Mutex;

pub struct MachineATronBackedRedfishClientPool {
    inner: libredfish::RedfishClientPool,
    // host_machines is intended to be mutable: We need to dynamically add machines to this pool as
    // machine-a-tron constructs them. This is because we need to pass a RedfishClientPool to the
    // API server when it initializes, but the API server needs to be already running in order to
    // construct a machine-a-tron context. So we start with an empty vec and add machines when
    // machine-a-tron starts up.
    pub host_machines: Mutex<Vec<Arc<Mutex<HostMachine>>>>,
}

impl MachineATronBackedRedfishClientPool {
    pub fn new() -> MachineATronBackedRedfishClientPool {
        let rf_pool = libredfish::RedfishClientPool::builder().build().unwrap();
        MachineATronBackedRedfishClientPool {
            inner: rf_pool,
            host_machines: Mutex::new(Vec::new()),
        }
    }
}

impl MachineATronBackedRedfishClientPool {
    async fn bmc_mock_addr_for_machine_ip(&self, address: &Ipv4Addr) -> Option<SocketAddr> {
        for host in self.host_machines.lock().await.iter() {
            let host = host.lock().await;

            // If the machine BMC has this address and is running the BMC mock, return the address
            // of that mock
            if let Some(bmc_dhcp_info) = host.bmc_dhcp_info.as_ref() {
                if bmc_dhcp_info.ip_address.eq(address) {
                    return host.bmc.as_ref().and_then(|b| b.active_address());
                }
            }

            // Look at the DPUs for this machine
            for dpu in host.dpu_machines.iter() {
                if let Some(bmc_dhcp_info) = dpu.bmc_dhcp_info.as_ref() {
                    if bmc_dhcp_info.ip_address.eq(address) {
                        return dpu.bmc.as_ref().and_then(|b| b.active_address());
                    }
                }
            }
        }
        None
    }
}

#[async_trait]
impl RedfishClientPool for MachineATronBackedRedfishClientPool {
    async fn create_client(
        &self,
        host: &str,
        port: Option<u16>,
        auth: RedfishAuth,
        initialize: bool,
    ) -> Result<Box<dyn Redfish>, RedfishClientCreationError> {
        self.create_client_with_custom_headers(host, port, &[], auth, initialize)
            .await
    }

    async fn create_client_from_machine_snapshot(
        &self,
        target: &MachineSnapshot,
        _txn: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    ) -> Result<Box<dyn Redfish>, RedfishClientCreationError> {
        let machine_id = &target.machine_id;

        let maybe_ip = target.bmc_info.ip.as_ref().ok_or_else(|| {
            RedfishClientCreationError::MissingBmcEndpoint(format!(
                "BMC Endpoint Information (bmc_info.ip) is missing for {}",
                machine_id
            ))
        })?;

        let ip: IpAddr = maybe_ip.parse().map_err(|_| {
            RedfishClientCreationError::InvalidArgument(
                format!("Invalid IP address for {}", machine_id),
                maybe_ip.into(),
            )
        })?;

        self.create_client(
            ip.to_string().as_str(),
            target.bmc_info.port,
            RedfishAuth::Anonymous,
            true,
        )
        .await
    }

    /// Create a client, but instead of connecting to the requested ip:port, look for the machine
    /// (or DPU) in the list of machine-a-tron mocks that has that particular IP, and connect to its
    /// BMC mock instead (which may be listening on a different port, to avoid allocating IP's in
    /// tests.) If the IP isn't found, or if the bmc-mock isn't listening, return an error.
    async fn create_client_with_custom_headers(
        &self,
        host: &str,
        _port: Option<u16>,
        custom_headers: &[(String, String)],
        _auth: RedfishAuth,
        _initialize: bool,
    ) -> Result<Box<dyn Redfish>, RedfishClientCreationError> {
        let Ok(ip_addr) = Ipv4Addr::from_str(host) else {
            tracing::error!("libredfish is attempting to connect to a host via an invalid IP address: {}. Note: hostnames are not supported in mock BMC's.", host);
            return Err(RedfishClientCreationError::NotImplemented);
        };

        let Some(addr) = self.bmc_mock_addr_for_machine_ip(&ip_addr).await else {
            tracing::info!("could not create redfish client: BMC mock is not listening for {host}");
            return Err(RedfishClientCreationError::NotImplemented);
        };

        let custom_headers = custom_headers
            .iter()
            .map(|(header_str, value_str)| {
                let header: HeaderName = HeaderName::from_str(header_str)
                    .map_err(RedfishClientCreationError::InvalidHeader)?;
                Ok((header, value_str.clone()))
            })
            .collect::<Result<Vec<(HeaderName, String)>, RedfishClientCreationError>>()?;

        self.inner
            .create_client_with_custom_headers(
                Endpoint {
                    host: addr.ip().to_string(),
                    port: Some(addr.port()),
                    password: None,
                    user: None,
                },
                custom_headers,
            )
            .await
            .map_err(RedfishClientCreationError::RedfishError)
    }

    async fn create_forge_admin_user(
        &self,
        _client: &dyn Redfish,
        _machine_id: String,
    ) -> Result<(), RedfishClientCreationError> {
        Ok(())
    }

    async fn uefi_setup(
        &self,
        _client: &dyn Redfish,
        _dpu: bool,
    ) -> Result<Option<String>, RedfishClientCreationError> {
        Ok(None)
    }
}
