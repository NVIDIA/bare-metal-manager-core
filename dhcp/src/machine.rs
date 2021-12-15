use crate::discovery::Discovery;
use crate::pxe::Architectures;
use log::error;
use std::ffi::CString;
use std::net::Ipv4Addr;
use std::primitive::u32;

/// Machine: a machine that's currently trying to boot something
///
/// This just stores the protobuf DHCP record and the discovery info the client used so we can add
/// additional constraints (options) to and from the client.
///
#[derive(Debug)]
pub struct Machine {
    pub(crate) inner: rpc::v0::DhcpRecord,
    pub(crate) discovery_info: Discovery,
}

/// Get the router address
///
/// # Safety
///
/// This function deferences a pointer to a Machine object which is an opaque pointer
/// consumed in C code.
///
#[no_mangle]
pub extern "C" fn machine_get_interface_router(ctx: *mut Machine) -> u32 {
    assert!(!ctx.is_null());
    let machine = unsafe { Box::from_raw(ctx) };
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
pub extern "C" fn machine_get_interface_address(ctx: *mut Machine) -> u32 {
    assert!(!ctx.is_null());
    let machine = unsafe { Box::from_raw(ctx) };

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
pub extern "C" fn machine_get_interface_hostname(ctx: *mut Machine) -> *mut libc::c_char {
    assert!(!ctx.is_null());
    let machine = unsafe { Box::from_raw(ctx) };

    let fqdn = CString::new(&machine.inner.fqdn[..]).unwrap();

    std::mem::forget(machine);

    fqdn.into_raw()
}

/// Get the machine fqdn
///
/// # Safety
/// This function checks for null pointer and unboxes into a machine object
///
#[no_mangle]
pub extern "C" fn machine_get_filename(ctx: *mut Machine) -> *mut libc::c_char {
    assert!(!ctx.is_null());
    let machine = unsafe { Box::from_raw(ctx) };

    let fqdn = match Architectures::find(machine.discovery_info.client_system) {
        Some(arch) => CString::new(arch.filename()).unwrap_or_else(|err| {
            error!("Couldn't convert {} to CString: {}", arch, err);
            CString::new("").unwrap()
        }),
        None => CString::new("ipxe.kpxe").unwrap(),
    };

    std::mem::forget(machine);

    fqdn.into_raw()
}

#[no_mangle]
pub extern "C" fn machine_get_next_server(ctx: *mut Machine) -> u32 {
    assert!(!ctx.is_null());
    let machine = unsafe { Box::from_raw(ctx) };

    let ret = u32::from_be_bytes("172.16.0.110".parse::<Ipv4Addr>().unwrap().octets());

    std::mem::forget(machine);

    ret
}

#[no_mangle]
pub extern "C" fn machine_get_uuid(ctx: *mut Machine) -> *mut libc::c_char {
    assert!(!ctx.is_null());
    let machine = unsafe { Box::from_raw(ctx) };

    let uuid = if let Some(machine_id) = &machine.inner.machine_id {
        CString::new(machine_id.to_string()).unwrap()
    } else {
        error!("Found a host missing UUID, dumping everything we know about it: {:?}", &machine);
        CString::new("").unwrap()
    };

    std::mem::forget(machine);

    uuid.into_raw()
}

#[no_mangle]
pub extern "C" fn machine_get_broadcast_address(ctx: *mut Machine) -> u32 {
    assert!(!ctx.is_null());
    let machine = unsafe { Box::from_raw(ctx) };

    let ret = u32::from_be_bytes("192.168.0.255".parse::<Ipv4Addr>().unwrap().octets());

    std::mem::forget(machine);

    ret
}

#[no_mangle]
pub extern "C" fn machine_free_filename(filename: *mut libc::c_char) {
    unsafe {
        if filename.is_null() {
            return;
        }

        CString::from_raw(filename)
    };
}

#[no_mangle]
pub extern "C" fn machine_free_uuid(uuid: *mut libc::c_char) {
    unsafe {
        if uuid.is_null() {
            return;
        }

        CString::from_raw(uuid)
    };
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

#[no_mangle]
pub extern "C" fn machine_free_next_server(next_server: *mut libc::c_char) {
    unsafe {
        if next_server.is_null() {
            return;
        }

        CString::from_raw(next_server)
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
pub extern "C" fn machine_get_interface_subnet_mask(ctx: *mut Machine) -> u32 {
    assert!(!ctx.is_null());
    let machine = unsafe { Box::from_raw(ctx) };

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
pub extern "C" fn machine_free(ctx: *mut Machine) {
    if ctx.is_null() {
        return;
    }

    unsafe { Box::from_raw(ctx) };
}
