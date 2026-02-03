use std::collections::HashMap;
use std::net::IpAddr;

use mac_address::MacAddress;
use model::expected_machine::ExpectedMachine;
use model::expected_power_shelf::ExpectedPowerShelf;
use model::expected_switch::ExpectedSwitch;
use model::machine::MachineInterfaceSnapshot;
use model::site_explorer::ExploredEndpoint;

/// An index into explored endpoints, allowing looking up expected endpoints by their MAC address,
/// and by the IP address of the explored endpoint, if one was found.
pub struct ExploredEndpointIndex {
    explored_underlay_interfaces: HashMap<MacAddress, MachineInterfaceSnapshot>,
    explored_endpoints: HashMap<IpAddr, ExploredEndpoint>,
    expected_machines: HashMap<MacAddress, ExpectedMachine>,
    expected_power_shelves: HashMap<MacAddress, ExpectedPowerShelf>,
    expected_switches: HashMap<MacAddress, ExpectedSwitch>,

    // 2-level index: Look up the IpAddr to get the MacAddress, then look that up to get the actual data.
    underlay_interfaces_addr_index: HashMap<IpAddr, MacAddress>,
    explored_machines_addr_index: HashMap<IpAddr, MacAddress>,
    explored_power_shelves_addr_index: HashMap<IpAddr, MacAddress>,
    explored_switches_addr_index: HashMap<IpAddr, MacAddress>,
}

impl ExploredEndpointIndex {
    pub fn builder(
        explored_endpoints: Vec<ExploredEndpoint>,
        explored_underlay_interfaces: Vec<MachineInterfaceSnapshot>,
    ) -> ExploredEndpointIndexBuilder {
        ExploredEndpointIndexBuilder::new(explored_endpoints, explored_underlay_interfaces)
    }

    /// Get a HashMap of explored endpoints, indexed by their IP address
    pub fn explored_endpoints(&self) -> &HashMap<IpAddr, ExploredEndpoint> {
        &self.explored_endpoints
    }

    /// Get a HashMap of expected machines, indexed by their MAC address
    pub fn expected_machines(&self) -> &HashMap<MacAddress, ExpectedMachine> {
        &self.expected_machines
    }

    /// Get the underlay interface from `explored_underlay_interfaces` with the given address.
    pub fn underlay_interface(&self, addr: &IpAddr) -> Option<&MachineInterfaceSnapshot> {
        self.underlay_interfaces_addr_index
            .get(addr)
            .and_then(|mac| self.explored_underlay_interfaces.get(mac))
    }

    /// Get the [`ExpectedMachine`] that was matched with an ExploredEndpoint, if one was given.
    pub fn matched_expected_machine(&self, addr: &IpAddr) -> Option<&ExpectedMachine> {
        self.explored_machines_addr_index
            .get(addr)
            .and_then(|mac| self.expected_machines.get(mac))
    }

    /// Get the [`ExpectedPowerShelf`] that was matched with an ExploredEndpoint, if one was given.
    pub fn matched_expected_power_shelf(&self, addr: &IpAddr) -> Option<&ExpectedPowerShelf> {
        self.explored_power_shelves_addr_index
            .get(addr)
            .and_then(|mac| self.expected_power_shelves.get(mac))
    }

    /// Get the [`ExpectedSwitch`] that was matched with an ExploredEndpoint, if one was given.
    pub fn matched_expected_switch(&self, addr: &IpAddr) -> Option<&ExpectedSwitch> {
        self.explored_switches_addr_index
            .get(addr)
            .and_then(|mac| self.expected_switches.get(mac))
    }

    /// Get [`MachineInterfaceSnapshot`]s from `explored_underlay_interfaces` that do not have
    /// corresponding [`ExploredEndpoints`] in the index.
    pub fn get_unexplored_endpoints(&self) -> Vec<(IpAddr, &MachineInterfaceSnapshot)> {
        self.underlay_interfaces_addr_index
            .iter()
            .filter_map(|(address, mac)| {
                if self.explored_endpoints.contains_key(address) {
                    None
                } else {
                    let iface = self.explored_underlay_interfaces
                        .get(mac)
                        // These two indexes should always stay in sync.
                        .expect("BUG: index is inconsistent, explored_underlay_interfaces and underlay_interfaces_addr_index do not match");
                    Some((*address, iface))
                }
            })
            .collect()
    }

    /// Return the expected machines that were found in `explored_underlay_interfaces`
    pub fn all_matched_expected_machines(&self) -> HashMap<MacAddress, &ExpectedMachine> {
        self.expected_machines
            .iter()
            .filter_map(|(mac, expected_machine)| {
                if self.explored_underlay_interfaces.contains_key(mac) {
                    Some((*mac, expected_machine))
                } else {
                    None
                }
            })
            .collect()
    }
}

/// Builder for ExploredEndpointIndex, allowing us to have the "writable" index be mutually
/// exclusive to the "readable" version of it.
///
/// You can insert data into an ExploredEndpointIndexBuilder, but you can only read from a built
/// ExploredEndpointIndex, which is only available after moving (consuming) the builder via
/// .build(). This is to prevent strange ordering bugs if we try to insert more data after reading
/// values out of it.
pub struct ExploredEndpointIndexBuilder {
    explored_underlay_interfaces: HashMap<MacAddress, MachineInterfaceSnapshot>,
    explored_endpoints: HashMap<IpAddr, ExploredEndpoint>,
    expected_machines: HashMap<MacAddress, ExpectedMachine>,
    expected_power_shelves: HashMap<MacAddress, ExpectedPowerShelf>,
    expected_switches: HashMap<MacAddress, ExpectedSwitch>,

    // 2-level index: Look up the IpAddr to get the MacAddress, then look that up to get the actual data.
    underlay_interfaces_addr_index: HashMap<IpAddr, MacAddress>,
    explored_machines_addr_index: HashMap<IpAddr, MacAddress>,
    explored_power_shelves_addr_index: HashMap<IpAddr, MacAddress>,
    explored_switches_addr_index: HashMap<IpAddr, MacAddress>,
}

impl ExploredEndpointIndexBuilder {
    pub fn new(
        explored_endpoints: Vec<ExploredEndpoint>,
        explored_underlay_interfaces: Vec<MachineInterfaceSnapshot>,
    ) -> Self {
        let explored_underlay_interfaces: HashMap<MacAddress, MachineInterfaceSnapshot> =
            explored_underlay_interfaces
                .into_iter()
                .map(|i| (i.mac_address, i))
                .collect();
        let underlay_interfaces_addr_index: HashMap<IpAddr, MacAddress> =
            explored_underlay_interfaces
                .values()
                .flat_map(|iface| {
                    iface
                        .addresses
                        .iter()
                        .map(move |addr| (*addr, iface.mac_address))
                })
                .collect();
        let explored_endpoints = explored_endpoints
            .into_iter()
            .map(|e| (e.address, e))
            .collect();
        Self {
            explored_underlay_interfaces,
            underlay_interfaces_addr_index,
            explored_endpoints,
            expected_machines: Default::default(),
            expected_power_shelves: Default::default(),
            expected_switches: Default::default(),
            explored_machines_addr_index: Default::default(),
            explored_power_shelves_addr_index: Default::default(),
            explored_switches_addr_index: Default::default(),
        }
    }

    pub fn with_expected_power_shelves(mut self, shelves: Vec<ExpectedPowerShelf>) -> Self {
        for shelf in shelves {
            tracing::info!(
                "expected_power_shelf from DB: {} {}",
                shelf.bmc_mac_address,
                shelf.metadata.name
            );
            if let Some(iface) = self
                .explored_underlay_interfaces
                .get(&shelf.bmc_mac_address)
            {
                tracing::info!(
                    "iface mac address {} expected power shelf mac address {}",
                    iface.mac_address,
                    shelf.bmc_mac_address
                );
                for addr in &iface.addresses {
                    self.explored_power_shelves_addr_index
                        .insert(*addr, shelf.bmc_mac_address);
                }
            }
            self.expected_power_shelves
                .insert(shelf.bmc_mac_address, shelf);
        }
        self
    }

    pub fn with_expected_switches(mut self, switches: Vec<ExpectedSwitch>) -> Self {
        // Create a mapping of expected switches by IP address and MAC address
        for switch in switches {
            tracing::info!(
                "expected_switch from DB: {} {}",
                switch.bmc_mac_address,
                switch.metadata.name
            );
            if let Some(iface) = self
                .explored_underlay_interfaces
                .get(&switch.bmc_mac_address)
            {
                tracing::info!(
                    "iface mac address {} expected switch mac address {}",
                    iface.mac_address,
                    switch.bmc_mac_address
                );
                for addr in &iface.addresses {
                    self.explored_switches_addr_index
                        .insert(*addr, switch.bmc_mac_address);
                }
            }
            self.expected_switches
                .insert(switch.bmc_mac_address, switch);
        }
        self
    }

    pub fn with_expected_machines(mut self, machines: Vec<ExpectedMachine>) -> Self {
        for machine in machines {
            if let Some(iface) = self
                .explored_underlay_interfaces
                .get(&machine.bmc_mac_address)
            {
                for addr in &iface.addresses {
                    self.explored_machines_addr_index
                        .insert(*addr, machine.bmc_mac_address);
                }
            }
            self.expected_machines
                .insert(machine.bmc_mac_address, machine);
        }
        self
    }

    pub fn build(self) -> ExploredEndpointIndex {
        ExploredEndpointIndex {
            explored_underlay_interfaces: self.explored_underlay_interfaces,
            explored_endpoints: self.explored_endpoints,
            expected_machines: self.expected_machines,
            expected_power_shelves: self.expected_power_shelves,
            expected_switches: self.expected_switches,
            underlay_interfaces_addr_index: self.underlay_interfaces_addr_index,
            explored_machines_addr_index: self.explored_machines_addr_index,
            explored_power_shelves_addr_index: self.explored_power_shelves_addr_index,
            explored_switches_addr_index: self.explored_switches_addr_index,
        }
    }
}
