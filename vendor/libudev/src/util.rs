use std::slice;
use std::ffi::{CString, OsStr};
use std::path::Path;

use libc::{c_int, c_char};

use std::os::unix::prelude::*;

#[inline(always)]
pub fn ptr_to_path<'a>(ptr: *const c_char) -> Option<&'a Path> {
    match ptr_to_os_str(ptr) {
        Some(path) => Some(Path::new(path)),
        None => None,
    }
}

#[inline(always)]
pub fn ptr_to_os_str<'a>(ptr: *const c_char) -> Option<&'a OsStr> {
    if !ptr.is_null() {
        Some(unsafe { ptr_to_os_str_unchecked(ptr) })
    }
    else {
        None
    }
}

#[inline(always)]
pub unsafe fn ptr_to_os_str_unchecked<'a>(ptr: *const c_char) -> &'a OsStr {
    OsStr::from_bytes(slice::from_raw_parts(ptr as *const u8, ::libc::strlen(ptr) as usize))
}

#[inline(always)]
pub fn os_str_to_cstring<T: AsRef<OsStr>>(s: T) -> ::Result<CString> {
    match CString::new(s.as_ref().as_bytes()) {
        Ok(s) => Ok(s),
        Err(_) => return Err(::error::from_errno(::libc::EINVAL)),
    }
}

#[inline(always)]
pub fn errno_to_result(errno: c_int) -> ::Result<()> {
    match errno {
        0 => Ok(()),
        e => Err(::error::from_errno(e)),
    }
}
