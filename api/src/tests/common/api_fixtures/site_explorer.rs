use std::{collections::HashMap, future::Future, iter, net::IpAddr, str::FromStr};

use crate::{
    db,
    db::explored_endpoints::DbExploredEndpoint,
    model::{
        hardware_info::HardwareInfo, machine::ManagedHostStateSnapshot,
        site_explorer::EndpointExplorationReport,
    },
};
use forge_uuid::machine::MachineId;
use rpc::{forge, forge::forge_server::Forge, DiscoveryData, DiscoveryInfo};

use crate::tests::common::api_fixtures::{
    dpu::DpuConfig,
    managed_host::ManagedHostConfig,
    network_segment::{
        FIXTURE_ADMIN_NETWORK_SEGMENT_GATEWAY, FIXTURE_HOST_INBAND_NETWORK_SEGMENT_GATEWAY,
        FIXTURE_UNDERLAY_NETWORK_SEGMENT_GATEWAY,
    },
    TestEnv,
};

/// MockExploredHost presents a fluent interface for declaring a mock host and running it through
/// the site-explorer ingestion lifecycle. Its methods are intended to be chained together to
/// script together a sequence of expected events to ingest a mock host.
pub struct MockExploredHost<'a> {
    pub test_env: &'a TestEnv,
    pub managed_host: ManagedHostConfig,
    pub host_bmc_ip: Option<IpAddr>,
    pub dpu_bmc_ips: HashMap<u8, IpAddr>,
    pub host_dhcp_response: Option<forge::DhcpRecord>,
    pub machine_discovery_response: Option<forge::MachineDiscoveryResult>,
}

impl<'a> MockExploredHost<'a> {
    pub fn new(test_env: &'a TestEnv, managed_host: ManagedHostConfig) -> Self {
        Self {
            test_env,
            managed_host,
            host_bmc_ip: None,
            dpu_bmc_ips: HashMap::new(),
            host_dhcp_response: None,
            machine_discovery_response: None,
        }
    }

    /// Simulate the host's BMC interface getting DHCP.
    ///
    /// Yields the result to the passed closure.
    pub async fn discover_dhcp_host_bmc<
        F: FnOnce(tonic::Result<tonic::Response<forge::DhcpRecord>>, &mut Self) -> eyre::Result<()>,
    >(
        mut self,
        f: F,
    ) -> eyre::Result<Self> {
        let result = self
            .test_env
            .api
            .discover_dhcp(tonic::Request::new(forge::DhcpDiscovery {
                mac_address: self.managed_host.bmc_mac_address.to_string(),
                relay_address: FIXTURE_UNDERLAY_NETWORK_SEGMENT_GATEWAY.ip().to_string(),
                link_address: None,
                vendor_string: Some("SomeVendor".to_string()),
                circuit_id: None,
                remote_id: None,
            }))
            .await;

        if let Ok(ref response) = result {
            self.host_bmc_ip = Some(response.get_ref().address.parse()?);
        }

        f(result, &mut self)?;
        Ok(self)
    }

    /// Simulate the given DPU's (indicated by dpu_index) BMC interface getting DHCP. Will panic if
    /// the index is out of range (ie. not part of the ManagedHostConfig.)
    ///
    /// Yields the result to the passed closure.
    pub async fn discover_dhcp_dpu_bmc<
        F: FnOnce(tonic::Result<tonic::Response<forge::DhcpRecord>>, &mut Self) -> eyre::Result<()>,
    >(
        mut self,
        dpu_index: u8,
        f: F,
    ) -> eyre::Result<Self> {
        let result = self
            .test_env
            .api
            .discover_dhcp(tonic::Request::new(forge::DhcpDiscovery {
                mac_address: self.managed_host.dpus[dpu_index as usize]
                    .bmc_mac_address
                    .to_string(),
                relay_address: FIXTURE_UNDERLAY_NETWORK_SEGMENT_GATEWAY.ip().to_string(),
                link_address: None,
                vendor_string: Some("SomeVendor".to_string()),
                circuit_id: None,
                remote_id: None,
            }))
            .await;

        if let Ok(ref response) = result {
            self.dpu_bmc_ips
                .insert(dpu_index, response.get_ref().address.parse()?);
        }

        f(result, &mut self)?;
        Ok(self)
    }

    // Create an EndpointExplorationReport for the host and DPUs, and seed them into the
    // MockEndpointExplorer in this test env. If any of the host BMC or DPU BMC's have not run DHCP
    // yet, they will be skipped (as we won't yet know their IP.)
    pub async fn insert_site_exploration_results(self) -> eyre::Result<Self> {
        self.test_env.endpoint_explorer.insert_endpoints(
            self.managed_host
                .dpus
                .iter()
                .enumerate()
                .filter_map(|(index, dpu)| {
                    let mut report: EndpointExplorationReport = dpu.clone().into();
                    report.generate_machine_id(false).unwrap();
                    Some((*self.dpu_bmc_ips.get(&(index as u8))?, dpu.clone().into()))
                })
                .chain(
                    iter::once(
                        self.host_bmc_ip
                            .map(|ip| (ip, self.managed_host.clone().into())),
                    )
                    .flatten(),
                )
                .collect(),
        );
        Ok(self)
    }

    /// Run DHCP on the host's primary interface. If there are DPU's in the ManagedHostConfig, it
    /// uses the host_mac_address of the first DPU. If there are no DPUs, it uses the first mac
    /// address in [`ManagedHostConfig#non_dpu_macs`]. If there are none of those, panics.
    ///
    /// Yields the DHCP result to the passed closure
    pub async fn discover_dhcp_host_primary_iface<
        F: FnOnce(tonic::Result<tonic::Response<forge::DhcpRecord>>, &mut Self) -> eyre::Result<()>,
    >(
        mut self,
        f: F,
    ) -> eyre::Result<Self> {
        // Run dhcp from primary interface
        let relay_address = if self.managed_host.dpus.is_empty() {
            // zero-DPU machines DHCP from a HostInband segment
            FIXTURE_HOST_INBAND_NETWORK_SEGMENT_GATEWAY.ip().to_string()
        } else {
            FIXTURE_ADMIN_NETWORK_SEGMENT_GATEWAY.ip().to_string()
        };

        let result = self
            .test_env
            .api
            .discover_dhcp(tonic::Request::new(forge::DhcpDiscovery {
                mac_address: self.managed_host.dhcp_mac_address().to_string(),
                relay_address,
                vendor_string: Some("Bluefield".to_string()),
                link_address: None,
                circuit_id: None,
                remote_id: None,
            }))
            .await;
        if let Ok(ref response) = result {
            self.host_dhcp_response = Some(response.get_ref().clone());
        }
        f(result, &mut self)?;
        Ok(self)
    }

    /// Simulates scout running machine discovery on the managed host.
    ///
    /// Yields the discovery result to the passed closure.
    pub async fn discover_machine<
        F: FnOnce(
            tonic::Result<tonic::Response<forge::MachineDiscoveryResult>>,
            &mut Self,
        ) -> eyre::Result<()>,
    >(
        mut self,
        f: F,
    ) -> eyre::Result<Self> {
        // Run scout discovery from the host
        let result = self
            .test_env
            .api
            .discover_machine(tonic::Request::new(rpc::MachineDiscoveryInfo {
                machine_interface_id: Some(
                    self.host_dhcp_response
                        .as_ref()
                        .unwrap()
                        .machine_interface_id
                        .as_ref()
                        .unwrap()
                        .clone(),
                ),
                create_machine: true,
                discovery_data: Some(DiscoveryData::Info(DiscoveryInfo::try_from(
                    HardwareInfo::from(&self.managed_host),
                )?)),
            }))
            .await;

        if let Ok(ref response) = result {
            self.machine_discovery_response = Some(response.get_ref().clone());
        }

        f(result, &mut self)?;
        Ok(self)
    }

    /// Runs one iteration of site explorer in the test env.
    pub async fn run_site_explorer_iteration(self) -> Self {
        self.test_env.run_site_explorer_iteration().await;
        self
    }

    /// Marks all BMC IP's as having completed preingestion, manually using the database.
    pub async fn mark_preingestion_complete(self) -> eyre::Result<Self> {
        let ips = self
            .dpu_bmc_ips
            .values()
            .cloned()
            .chain(iter::once(self.host_bmc_ip.unwrap()))
            .collect::<Vec<_>>();
        let mut txn = self.test_env.pool.begin().await?;
        for ip in ips {
            DbExploredEndpoint::set_preingestion_complete(ip, &mut txn).await?;
        }
        txn.commit().await?;
        Ok(self)
    }

    /// Run the passed closure with a mutable referece to self
    pub async fn then<F, C: FnOnce(&mut Self) -> F>(mut self, f: C) -> eyre::Result<Self>
    where
        F: Future<Output = eyre::Result<()>>,
    {
        f(&mut self).await?;
        Ok(self)
    }

    /// Move self to the passed closure and return the closure's result. Useful as the final step of
    /// a method chain to return a final result.
    pub async fn finish<R, F, C: FnOnce(Self) -> F>(self, f: C) -> R
    where
        F: Future<Output = R>,
    {
        f(self).await
    }
}

/// Use this function to make a new managed  host with a given number of DPUs, using site-explorer
/// to ingest it into the database.
pub async fn new_host(env: &TestEnv, dpu_count: u8) -> eyre::Result<ManagedHostStateSnapshot> {
    let managed_host =
        ManagedHostConfig::with_dpus((0..dpu_count).map(|_| DpuConfig::default()).collect());
    let mut mock_explored_host = MockExploredHost::new(env, managed_host);

    // Run BMC DHCP. DPUs first...
    for dpu_index in 0..dpu_count {
        mock_explored_host = mock_explored_host
            .discover_dhcp_dpu_bmc(dpu_index, |_, _| Ok(()))
            .await?;
    }

    mock_explored_host
        // ...Then run host BMC's DHCP
        .discover_dhcp_host_bmc(|_, _| Ok(()))
        .await?
        .insert_site_exploration_results()
        .await?
        .run_site_explorer_iteration()
        .await
        .mark_preingestion_complete()
        .await?
        .run_site_explorer_iteration()
        .await
        .discover_dhcp_host_primary_iface(|_, _| Ok(()))
        .await?
        .discover_machine(|_, _| Ok(()))
        .await?
        .run_site_explorer_iteration()
        .await
        .finish(|mock| async move {
            let machine_id = mock.machine_discovery_response.unwrap().machine_id.unwrap();
            let mut txn = mock.test_env.pool.begin().await.unwrap();
            Ok(db::managed_host::load_snapshot(
                &mut txn,
                &MachineId::from_str(&machine_id.id)?,
                Default::default(),
            )
            .await
            .transpose()
            .unwrap()?)
        })
        .await
}
