use std::collections::HashMap;
use std::fmt::Debug;
use std::net::IpAddr;
use std::path::PathBuf;

use eyre::WrapErr;
use ipnetwork::IpNetwork;
use serde::{Deserialize, Serialize};
use tracing::log::error;

use crate::dpu::link::IpLink;
use crate::dpu::{Action, DpuNetworkInterfaces};
use crate::pretty_cmd;

// "Add", pf0dpu0_sf, Some(vec![IpNetwork]])
// ip addr add 169.254.169.254/30 dev pf0dpu0_sf
pub(crate) type DpuNetworkInterfacePlan = HashMap<Action, HashMap<String, Option<Vec<IpNetwork>>>>;

#[derive(Debug, Serialize, Deserialize, PartialEq, Clone)]
pub struct IpInterface {
    #[serde(flatten)]
    pub link: IpLink,
    pub addr_info: Vec<IpInterfaceAddress>,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Clone)]
pub struct IpInterfaceAddress {
    pub family: String,
    pub local: IpAddr,
    pub prefixlen: u8,
    pub broadcast: Option<IpAddr>,
    pub scope: String,
    pub label: Option<String>,
    pub valid_life_time: u32,
    pub preferred_life_time: u32,
}

#[derive(Debug, Clone)]
pub struct Interface {
    /// Represents the current configuration of interfaces as described in the forge-dpu-agent configuration file
    /// Interfaces configured outside forge-dpu-agent are not represented here
    pub current: Vec<IpInterfaceAddress>,
    /// Represents the plan, a series of actions that are taken to reconcile the current configuration with the desired configuration
    pub desired: HashMap<String, Vec<IpNetwork>>,
}

impl Interface {
    pub async fn apply(plan: DpuNetworkInterfacePlan) -> eyre::Result<()> {
        for (action, interfaces) in plan {
            for (interface, networks) in interfaces {
                match action {
                    Action::Add => {
                        if let Some(networks) = networks {
                            if !networks.is_empty() {
                                tracing::info!(
                                    "Adding addresses {:?} to Interface {:?}",
                                    networks,
                                    interface
                                );

                                for network in networks {
                                    Interface::ip_addrs_add(&interface, network).await?;
                                }
                            }
                        }
                    }
                    Action::Remove => {
                        // We deliberately do not allow removing an ip address
                        unimplemented!("Remove Interface {:?} {:?}", interface, networks);
                    }
                }
            }
        }
        Ok(())
    }

    pub async fn plan(
        interface: &str,
        proposed: DpuNetworkInterfaces,
    ) -> eyre::Result<DpuNetworkInterfacePlan> {
        let mut interface_plan: DpuNetworkInterfacePlan = HashMap::new();

        // Convert the current addresses to a Vec of IpNetwork
        // filter out non-ipv4 addresses
        let current_addresses = Interface::current_addresses(interface)
            .await?
            .iter()
            .flat_map(|x| &x.addr_info)
            .filter_map(|y| {
                if let Ok(ip) = IpNetwork::new(y.local, y.prefixlen) {
                    if ipnetwork::IpNetwork::is_ipv4(&ip) {
                        Some(ip)
                    } else {
                        tracing::trace!("Interface has non-ipv4 address: {:?}, skipping...", ip);
                        None
                    }
                } else {
                    None
                }
            })
            .collect::<Vec<_>>();

        for (interface, mut proposed_addresses) in proposed.desired.into_iter() {
            // for each desired interface and address
            if let Some(iface) = IpLink::get_link_by_name(interface.as_str()).await? {
                // if the interface exists
                if let Some(ifname) = &iface.ifname {
                    // get all addresses for the interface
                    let addr = Interface::get_addresses_for_interface(ifname).await?;
                    if !addr.is_empty() && !proposed_addresses.is_empty() {
                        if let Some(common_networks) = Interface::find_common_addresses(
                            &current_addresses,
                            &proposed_addresses,
                        ) {
                            let network_clone = common_networks.clone();
                            tracing::trace!(
                                "Proposed addresses already present on interface {interface}: {:?}",
                                common_networks
                            );

                            // If the proposed addresses are already present on the interface
                            // remove them from the list
                            // TODO - this is a bit of a hack, we shouldy probably change this logic to that of
                            // the Route::plan
                            proposed_addresses.retain(|x| !network_clone.contains(x));
                        }
                        tracing::trace!(
                            "Proposed addresses needing to be added to {interface}: {:?}",
                            proposed_addresses
                        );
                        let entry = interface_plan.entry(Action::Add).or_default();
                        entry.insert(interface.clone(), Some(proposed_addresses.clone()));
                    }
                }
            } else {
                tracing::error!(
                    interface,
                    "FMDS cannot add IP address to non-existent interface"
                );
            }
        }
        Ok(interface_plan)
    }

    async fn ip_addrs(interface: &str) -> eyre::Result<String> {
        if cfg!(test) || std::env::var("NO_DPU_ARMOS_NETWORK").is_ok() {
            let test_data_dir = PathBuf::from(crate::dpu::ARMOS_TEST_DATA_DIR);

            std::fs::read_to_string(test_data_dir.join("ipaddr.json")).map_err(|e| {
                error!("Could not read ipaddr.json: {}", e);
                eyre::eyre!("Could not read ipaddr.json: {}", e)
            })
        } else {
            let mut cmd = tokio::process::Command::new("bash");
            cmd.args(vec!["-c", &format!("ip -j addr show dev {}", interface)]);
            cmd.kill_on_drop(true);

            let cmd_str = pretty_cmd(cmd.as_std());

            let output = tokio::time::timeout(crate::dpu::COMMAND_TIMEOUT, cmd.output())
                .await
                .wrap_err_with(|| format!("Timeout while running command: {:?}", cmd_str))??;

            let fout = String::from_utf8_lossy(&output.stdout).to_string();
            Ok(fout)
        }
    }

    pub async fn current_addresses(interface: &str) -> eyre::Result<Vec<IpInterface>> {
        let data = Self::ip_addrs(interface).await?;
        tracing::trace!("interface data from ip addr show: {data:?}");
        serde_json::from_str::<Vec<IpInterface>>(&data).map_err(|err| eyre::eyre!(err))
    }

    async fn ip_addrs_add(interface: &str, address: IpNetwork) -> eyre::Result<bool> {
        let cmdargs = format!(
            "ip addr add {}/{} dev {}",
            address.ip(),
            address.prefix(),
            interface
        );

        let mut cmd = tokio::process::Command::new("bash");
        cmd.args(vec!["-c", &cmdargs]);
        cmd.kill_on_drop(true);

        let cmd_str = pretty_cmd(cmd.as_std());
        tracing::trace!("Running command: {:?}", cmd_str);

        let output = tokio::time::timeout(crate::dpu::COMMAND_TIMEOUT, cmd.output())
            .await
            .wrap_err_with(|| format!("Timeout while running command: {:?}", cmd_str))??;

        let fout = String::from_utf8_lossy(&output.stdout).to_string();
        if output.status.success() {
            Ok(true)
        } else {
            tracing::error!("Failed to add address: {:?}", fout);
            Ok(false)
        }
    }

    pub async fn get_addresses_for_interface(
        interface: &str,
    ) -> eyre::Result<Vec<IpInterfaceAddress>> {
        let data = Self::ip_addrs(interface).await?;
        tracing::trace!("interfaces data from ip show: {:?}", data);
        let data =
            serde_json::from_str::<Vec<IpInterface>>(&data).map_err(|err| eyre::eyre!(err))?;
        let filtered_list: Vec<_> = data
            .into_iter()
            .filter(|iface| iface.link.ifname.as_deref() == Some(interface))
            .flat_map(|iface| iface.addr_info)
            .collect();

        Ok(filtered_list)
    }

    pub fn find_common_addresses(
        current_addresses: &[IpNetwork],
        proposed_addresses: &[IpNetwork],
    ) -> Option<Vec<IpNetwork>> {
        let res = proposed_addresses
            .iter()
            .filter(|x| current_addresses.contains(x))
            .copied()
            .collect::<Vec<_>>();

        if res.is_empty() {
            None
        } else {
            Some(res)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dpu::interface::IpInterface;
    use crate::dpu::DpuNetworkInterfaces;

    struct TestInterfaceData {
        pub current: Vec<IpInterface>,
        pub desired: HashMap<String, Vec<IpNetwork>>,
    }
    impl TestInterfaceData {
        pub async fn new() -> Self {
            Self {
                current: Interface::current_addresses("pf0dpu0_sf").await.unwrap(),
                desired: HashMap::new(),
            }
        }

        async fn setup_test_data() -> TestInterfaceData {
            let test_ip = IpNetwork::new(IpAddr::from([192, 168, 0, 5]), 30).unwrap();
            let test_ip2 = IpNetwork::new(IpAddr::from([192, 168, 0, 10]), 30).unwrap();
            let test_ip3 = IpNetwork::new(IpAddr::from([192, 168, 0, 1]), 30).unwrap();
            let mut data = TestInterfaceData::new().await;
            let test_plan = vec![("pf0dpu0_sf".to_string(), vec![test_ip, test_ip2, test_ip3])];
            let test: HashMap<String, Vec<IpNetwork>> = test_plan.into_iter().collect();
            data.desired = test;
            data
        }

        async fn to_plan(&self) -> DpuNetworkInterfacePlan {
            Interface::plan(
                "pf0dpu0_sf",
                DpuNetworkInterfaces {
                    desired: self.desired.clone(),
                },
            )
            .await
            .unwrap()
        }
    }

    #[tokio::test]
    async fn common_addresses() {
        let data = TestInterfaceData::setup_test_data().await;
        let current = data.current;

        let current_addresses = current
            .iter()
            .flat_map(|x| &x.addr_info)
            .filter_map(|y| {
                if let Ok(ip) = IpNetwork::new(y.local, y.prefixlen) {
                    if ipnetwork::IpNetwork::is_ipv4(&ip) {
                        Some(ip)
                    } else {
                        tracing::trace!("Interface has non-ipv4 address: {:?}, skipping...", ip);
                        None
                    }
                } else {
                    None
                }
            })
            .collect::<Vec<_>>();

        let proposed = vec![
            IpNetwork::new(IpAddr::from([192, 168, 0, 1]), 30).unwrap(),
            IpNetwork::new(IpAddr::from([192, 168, 0, 2]), 30).unwrap(),
        ];

        let common = Interface::find_common_addresses(&current_addresses, &proposed).unwrap();

        let expect = IpNetwork::new(IpAddr::from([192, 168, 0, 1]), 30).unwrap();

        assert_eq!(common, vec![expect]);
    }
    #[tokio::test]
    async fn current_interface_addresses() {
        let data = TestInterfaceData::setup_test_data().await;
        let current = data.current;
        assert_eq!(current[0].addr_info[0].local, IpAddr::from([127, 0, 0, 1]));
    }

    #[tokio::test]
    async fn new_ip_addresses_are_add_action() {
        let data = TestInterfaceData::setup_test_data().await;
        let plan = data.to_plan().await;

        let add = plan.get(&Action::Add).unwrap();

        let list_of_networks = add.get("pf0dpu0_sf").unwrap().clone().unwrap();

        assert_eq!(
            list_of_networks,
            vec![
                IpNetwork::new(IpAddr::from([192, 168, 0, 5]), 30).unwrap(),
                IpNetwork::new(IpAddr::from([192, 168, 0, 10]), 30).unwrap()
            ]
        );
    }

    #[tokio::test]
    async fn test_addresses() {
        let interface = Interface::get_addresses_for_interface("pf0dpu0_sf")
            .await
            .unwrap();
        tracing::trace!("Interface: {:?}", interface);

        assert_eq!(interface[0].prefixlen, 30);
        assert_eq!(interface[0].local, IpAddr::from([192, 168, 0, 1]));
    }

    #[tokio::test]
    async fn test_link() {
        let link = IpLink::get_link_by_name("pf0dpu0_sf")
            .await
            .unwrap()
            .unwrap();
        tracing::trace!("Link: {:?}", link);
        assert_eq!(link.ifindex, 16);
    }
}
