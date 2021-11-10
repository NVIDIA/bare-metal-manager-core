use std::net::{AddrParseError, Ipv4Addr};
use std::primitive::u32;
use std::str::FromStr;

use crate::discovery::Discovery;

#[derive(Debug)]
pub struct Machine {
    pub(crate) inner: rpc::v0::Machine,
    pub(crate) discovery_info: Box<Discovery>,
}

impl Machine {
    fn booting_interface(&self) -> Option<&rpc::v0::MachineInterface> {
        if let Some(booting_mac_address) = self.discovery_info.mac_address {
            self.inner.interfaces.iter().find(|interface| {
                match interface.parsed_mac_address() {
                    Ok(None) => false,
                    Ok(Some(interface_mac_address))
                        if interface_mac_address == booting_mac_address =>
                    {


                        true
                    }
                    Ok(Some(_)) => false,
                    Err(error) => {
                        // TODO log to the Kea logger
                        eprintln!(
                            "MacAddress on interface {0} was unparsable: {1}",
                            interface.id.as_ref().unwrap(),
                            error
                        );
                        false
                    }
                }
            })
        } else {
            eprintln!("Discovery info {:?} has no mac address?", &self.discovery_info);
            None
        }
    }

    fn booting_router_address_v4(&self) -> Result<Option<Ipv4Addr>, AddrParseError> {
        if let Some(_interface) = self.booting_interface() {
            Ok(Some(Ipv4Addr::from_str("192.168.0.1")?))
        } else {
            Ok(None)
        }
    }

    fn booting_interface_address_v4(&self) -> Result<Option<Ipv4Addr>, AddrParseError> {
        if let Some(interface) = self.booting_interface() {
            interface.parsed_address_ipv4()
        } else {
            Ok(None)
        }
    }

    fn booting_interface_subnet_mask(&self) -> Result<Option<Ipv4Addr>, AddrParseError> {
        if let Some(_interface) = self.booting_interface() {
            Ok(Some(Ipv4Addr::from_str("255.255.255.0")?))
        } else {
            Ok(None)
        }
    }
}

/// Get the router address
///
/// # Safety
///
/// This function deferences a pointer to a Machine object which is an opaque pointer
/// consumed in C code.
///
#[no_mangle]
pub unsafe extern "C" fn machine_get_interface_router(ctx: *mut Machine) -> u32 {
    assert!(!ctx.is_null());
    let machine = Box::from_raw(ctx);
    let ret = u32::from_be_bytes(
        machine
            .booting_router_address_v4()
            .unwrap()
            .unwrap()
            .octets(),
    );
    std::mem::forget(machine);
    ret
}

/// Invoke the discovery processs
///
/// # Safety
/// This function deferences a pointer to a Machine object which is an opaque pointer
/// consumed in C code.
///
#[no_mangle]
pub unsafe extern "C" fn machine_get_interface_address(ctx: *mut Machine) -> u32 {
    assert!(!ctx.is_null());
    let machine = Box::from_raw(ctx);

    // TODO: handle some errors
    let ret = u32::from_be_bytes(
        machine
            .booting_interface_address_v4()
            .unwrap()
            .unwrap()
            .octets(),
    );

    std::mem::forget(machine);
    ret
}

/// Invoke the discovery processs
///
/// # Safety
///
/// This function deferences a pointer to a Machine object which is an opaque pointer
/// consumed in C code.
///
#[no_mangle]
pub unsafe extern "C" fn machine_get_interface_subnet_mask(ctx: *mut Machine) -> u32 {
    assert!(!ctx.is_null());
    let machine = Box::from_raw(ctx);

    // TODO: handle some errors
    let ret = u32::from_be_bytes(machine.booting_subnet_mask().unwrap().unwrap().octets());

    std::mem::forget(machine);
    ret
}

/// Free the Machine object.
///
/// # Safety
///
/// This function deferences a pointer to a Machine object which is an opaque pointer
/// consumed in C code.
///
/// This does not forget the memory afterwards, so the opaque pointer in the C code is now
/// unusable.
///
#[no_mangle]
pub unsafe extern "C" fn machine_free(ctx: *mut Machine) {
    if ctx.is_null() {
        return;
    }

    Box::from_raw(ctx);
}

#[cfg(test)]
mod tests {
    use super::Discovery;
    use eui48::MacAddress;
    use rpc::v0::{Machine, MachineAction, MachineEvent, MachineInterface, MachineState};
    use std::net::Ipv4Addr;
    use std::str::FromStr;
    use std::time::SystemTime;

    use crate::machine::Machine as DhcpMachine;

    fn generate_discovery_info() -> Discovery {
        Discovery {
            relay_address: Some(Ipv4Addr::from_str("192.168.0.1").unwrap()),
            mac_address: Some(MacAddress::from_str("08:00:27:cc:46:36").unwrap()),
            vendor_string: None,
        }
    }

    fn uuid(uuid: &str) -> rpc::v0::Uuid {
        rpc::v0::Uuid { value: uuid.into() }
    }

    fn generate_machine() -> rpc::v0::Machine {
        Machine {
            id: Some(uuid("9f19d552-75ac-4912-bd0c-6f6fd3426719")),
            fqdn: String::from("jig-coffee.x.nvmetal.net"),
            created: Some(SystemTime::now().into()),
            modified: Some(SystemTime::now().into()),
            events: vec![MachineEvent {
                id: 3,
                machine_id: Some(uuid("9f19d552-75ac-4912-bd0c-6f6fd3426719")),
                event: MachineAction::Discover.into(),
                version: 1,
                time: Some(SystemTime::now().into()),
            }],
            interfaces: vec![MachineInterface {
                id: Some(uuid("14410184-b52e-46ec-bae8-6d3149978d98")),
                machine_id: Some(uuid("9f19d552-75ac-4912-bd0c-6f6fd3426719")),
                segment_id: Some(uuid("2ee4a4d3-2498-4ad8-9b1a-99a5a3aece05")),
                mac_address: String::from("08:00:27:cc:46:36"),
                address_ipv4: Some("192.168.0.100".into()),
                address_ipv6: Some("fc00::".into()),
            }],
            state: Some(MachineState {
                state: "new".into(),
            }),
        }
    }

    #[test]
    fn test_retrieve_proper_ip() {
        let machine = DhcpMachine {
            inner: generate_machine(),
            discovery_info: Box::new(generate_discovery_info()),
        };

        let desired_ip: Ipv4Addr = Ipv4Addr::from_str("192.168.0.100").unwrap();

        assert_eq!(machine.booting_interface_address_v4(), Ok(Some(desired_ip)));
    }

    #[test]
    fn test_retrieve_proper_gatewway() {
        let machine = DhcpMachine {
            inner: generate_machine(),
            discovery_info: Box::new(generate_discovery_info()),
        };

        let desired_ip: Ipv4Addr = Ipv4Addr::from_str("192.168.0.1").unwrap();

        assert_eq!(machine.(), Ok(Some(desired_ip)));
    }
}
