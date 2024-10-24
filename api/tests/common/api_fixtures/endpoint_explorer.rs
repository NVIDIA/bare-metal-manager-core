use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
    sync::{Arc, Mutex},
};

use carbide::{
    db::expected_machine::ExpectedMachine,
    model::{
        machine::MachineInterfaceSnapshot,
        site_explorer::{EndpointExplorationError, EndpointExplorationReport},
    },
    site_explorer::{EndpointExplorer, SiteExplorationMetrics},
};

/// EndpointExplorer which returns predefined data
#[derive(Clone, Default, Debug)]
pub struct MockEndpointExplorer {
    pub reports:
        Arc<Mutex<HashMap<IpAddr, Result<EndpointExplorationReport, EndpointExplorationError>>>>,
}

impl MockEndpointExplorer {
    pub fn insert_endpoint(&self, address: IpAddr, report: EndpointExplorationReport) {
        self.insert_endpoint_result(address, Ok(report))
    }

    pub fn insert_endpoints(&self, endpoints: Vec<(IpAddr, EndpointExplorationReport)>) {
        self.insert_endpoint_results(
            endpoints
                .into_iter()
                .map(|(addr, report)| (addr, Ok(report)))
                .collect(),
        )
    }

    pub fn insert_endpoint_result(
        &self,
        address: IpAddr,
        result: Result<EndpointExplorationReport, EndpointExplorationError>,
    ) {
        self.insert_endpoint_results(vec![(address, result)]);
    }

    pub fn insert_endpoint_results(
        &self,
        endpoints: Vec<(
            IpAddr,
            Result<EndpointExplorationReport, EndpointExplorationError>,
        )>,
    ) {
        let mut guard = self.reports.lock().unwrap();
        for (address, result) in endpoints {
            guard.insert(address, result);
        }
    }
}

#[async_trait::async_trait]
impl EndpointExplorer for MockEndpointExplorer {
    async fn check_preconditions(
        &self,
        _metrics: &mut SiteExplorationMetrics,
    ) -> Result<(), EndpointExplorationError> {
        Ok(())
    }
    async fn explore_endpoint(
        &self,
        bmc_ip_address: SocketAddr,
        _interface: &MachineInterfaceSnapshot,
        _expected: Option<ExpectedMachine>,
        _last_report: Option<&EndpointExplorationReport>,
    ) -> Result<EndpointExplorationReport, EndpointExplorationError> {
        tracing::info!("Endpoint {bmc_ip_address} is getting explored");
        let guard = self.reports.lock().unwrap();
        let res = guard.get(&bmc_ip_address.ip()).unwrap();
        res.clone()
    }

    async fn redfish_reset_bmc(
        &self,
        _address: SocketAddr,
        _interface: &MachineInterfaceSnapshot,
    ) -> Result<(), EndpointExplorationError> {
        Ok(())
    }

    async fn ipmitool_reset_bmc(
        &self,
        _address: SocketAddr,
        _interface: &MachineInterfaceSnapshot,
    ) -> Result<(), EndpointExplorationError> {
        Ok(())
    }

    async fn redfish_power_control(
        &self,
        _address: SocketAddr,
        _interface: &MachineInterfaceSnapshot,
        _action: libredfish::SystemPowerControl,
    ) -> Result<(), EndpointExplorationError> {
        Ok(())
    }

    async fn have_credentials(&self, _interface: &MachineInterfaceSnapshot) -> bool {
        true
    }

    async fn forge_setup(
        &self,
        _address: SocketAddr,
        _interface: &MachineInterfaceSnapshot,
    ) -> Result<(), EndpointExplorationError> {
        Ok(())
    }

    async fn forge_setup_status(
        &self,
        _address: SocketAddr,
        _interface: &MachineInterfaceSnapshot,
    ) -> Result<libredfish::ForgeSetupStatus, EndpointExplorationError> {
        Ok(libredfish::ForgeSetupStatus {
            is_done: true,
            diffs: vec![],
        })
    }
}
