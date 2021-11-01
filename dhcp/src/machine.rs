use std::net::Ipv4Addr;
use std::primitive::u32;
use std::str::FromStr;

use crate::discovery::Discovery;

#[derive(Debug)]
pub struct Machine {
    pub inner: rpc::v0::Machine,
    pub discovery_info: Option<Box<Discovery>>,
}

impl Machine {
    fn booting_interface(&self) -> Option<rpc::v0::MachineInterface> {
        None
    }

    fn booting_router_address(&self) -> Option<Ipv4Addr> {
        let _ = self.booting_interface();
        Some(Ipv4Addr::from_str("192.168.0.1").unwrap())
    }

    fn booting_interface_address(&self) -> Option<Ipv4Addr> {
        Some(Ipv4Addr::from_str("192.168.0.23").unwrap())
    }

    fn booting_subnet_mask(&self) -> Option<Ipv4Addr> {
        Some(Ipv4Addr::from_str("255.255.255.0").unwrap())
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
    let ret = u32::from_be_bytes(machine.booting_router_address().unwrap().octets());
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
    let ret = u32::from_be_bytes(machine.booting_interface_address().unwrap().octets());
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
    let ret = u32::from_be_bytes(machine.booting_subnet_mask().unwrap().octets());
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

//#[cfg(test)]
//mod tests {
//    #[test]
//    fn test_retrieve_proper_ip() {
//        let rpc = rpc::v0::Machine {
//            id: uuid::Uuid::new_v4(),
//        };
//    }
//}
