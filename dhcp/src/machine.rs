use std::ffi::CString;
use std::net::{AddrParseError, Ipv4Addr};
use std::primitive::u32;
use std::str::FromStr;

use crate::discovery::Discovery;

#[derive(Debug)]
pub struct Machine {
    pub(crate) inner: rpc::v0::DhcpRecord,
    pub(crate) discovery_info: Box<Discovery>,
}
impl Machine {
    fn interface_address_v4(&self) -> Result<Option<Ipv4Addr>, AddrParseError> {
        Ok(self
            .inner
            .address_ipv4
            .as_ref()
            .map(|a| Ipv4Addr::from_str(&a.address).unwrap()))
    }

    fn router_address_v4(&self) -> Result<Option<Ipv4Addr>, AddrParseError> {
        if let Some(address_assignment) = self.inner.address_ipv4.as_ref() {
            match address_assignment {
                rpc::v0::AddressAssignmentV4 {
                    gateway: Some(x), ..
                } => Ok(Some(Ipv4Addr::from_str(x)?)),
                _ => Ok(None),
            }
        } else {
            Ok(None)
        }
    }

    fn interface_fqdn(&self) -> &str {
        &self.inner.fqdn
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
            .inner
            .address_ipv4
            .as_ref()
            .map(|address| {
                address
                    .gateway
                    .as_ref()
                    .unwrap()
                    .parse::<Ipv4Addr>()
                    .unwrap()
            })
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
            .inner
            .address_ipv4
            .as_ref()
            .map(|address| address.address.parse::<Ipv4Addr>().unwrap())
            .unwrap()
            .octets(),
    );

    std::mem::forget(machine);
    ret
}

/// Get the machine fqdn
///
/// # Safety
/// This function checks for null pointer and unboxes into a machine object
///
#[no_mangle]
pub unsafe extern "C" fn machine_get_interface_hostname(ctx: *mut Machine) -> *mut libc::c_char {
    assert!(!ctx.is_null());
    let machine = Box::from_raw(ctx);

    let fqdn = CString::new(machine.interface_fqdn()).unwrap();

    std::mem::forget(machine);

    fqdn.into_raw()
}

#[no_mangle]
pub extern "C" fn machine_free_fqdn(fqdn: *mut libc::c_char) {
    unsafe {
        if fqdn.is_null() {
            return;
        }

        CString::from_raw(fqdn)
    };
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
    let ret = u32::from_be_bytes(
        machine
            .inner
            .address_ipv4
            .as_ref()
            .map(|address| address.mask.parse::<Ipv4Addr>().unwrap())
            .unwrap()
            .octets(),
    );

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
    use mac_address::MacAddress;

    use std::net::Ipv4Addr;
    use std::str::FromStr;


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

    fn generate_machine() -> rpc::v0::DhcpRecord {
        rpc::v0::DhcpRecord {
            machine_id: Some(uuid("9f19d552-75ac-4912-bd0c-6f6fd3426719")),
            segment_id: Some(uuid("2ee4a4d3-2498-4ad8-9b1a-99a5a3aece05")),
            fqdn: String::from("jig-coffee.test.nvmetal.net"),
            subdomain: "test.nvmetal.net".to_string(),
            address_ipv4: Some(rpc::v0::AddressAssignmentV4 {
                mac_address: MacAddress::from_str("08:00:27:cc:46:36")
                    .unwrap()
                    .to_string(),
                address: "192.168.0.4".parse().unwrap(),
                gateway: Some("192.168.0.1".parse().unwrap()),
                mask: "255.255.255.0".parse().unwrap(),
            }),
            address_ipv6: None,
        }
    }

    #[test]
    fn test_retrieve_proper_ip() {
        let machine = DhcpMachine {
            inner: generate_machine(),
            discovery_info: Box::new(generate_discovery_info()),
        };

        let desired_ip: Ipv4Addr = Ipv4Addr::from_str("192.168.0.4").unwrap();

        assert_eq!(machine.interface_address_v4(), Ok(Some(desired_ip)));
    }

    #[test]
    fn test_receive_proper_hostname() {
        let machine = DhcpMachine {
            inner: generate_machine(),
            discovery_info: Box::new(generate_discovery_info()),
        };

        let desired_hostname = machine.inner.fqdn;

        assert_eq!(machine.interface_fqdn(), "jig-coffee.test.nvmetal.net");
    }

    #[test]
    fn test_retrieve_proper_gatewway() {
        let machine = DhcpMachine {
            inner: generate_machine(),
            discovery_info: Box::new(generate_discovery_info()),
        };

        let desired_ip: Ipv4Addr = Ipv4Addr::from_str("192.168.0.1").unwrap();

        assert_eq!(machine.router_address_v4(), Ok(Some(desired_ip)));
    }
}
