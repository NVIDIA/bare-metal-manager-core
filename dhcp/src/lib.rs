use libc::c_int;

#[repr(C)] pub struct LibraryHandle {
    private: [u8; 0]
}

#[no_mangle]
extern fn version() -> c_int {
    20000
}

#[no_mangle]
extern fn load(_library: *mut LibraryHandle) -> c_int {
    0
}

#[no_mangle]
extern fn unload() -> c_int {
    0
}

#[no_mangle]
extern fn multi_threading_compatible() -> c_int {
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        assert_eq!(version(), 0);
    }
}
