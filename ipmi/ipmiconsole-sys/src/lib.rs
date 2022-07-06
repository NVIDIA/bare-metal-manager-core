#![allow(non_camel_case_types)]
// we want to match freeipmi names of structs and enums and defines, so we don't do camel case
#![allow(dead_code)]
#![allow(unused_imports)]

// WARNING: libipmiconsole is GPLv3!
// Including libipmiconsole headers directly probably means using its sources and creating a derived
// work.

use num_enum::IntoPrimitive;
use libc::{c_char, c_int, c_uint, c_void};
use errno::errno;

#[cfg(feature = "libc")]
// relevant enums from the c headers
#[repr(u8)]
#[derive(Copy, Clone, IntoPrimitive)]
/// Errors from libipmiconsole
pub enum ipmiconsole_errnum {
    IPMICONSOLE_ERR_SUCCESS = 0,
    IPMICONSOLE_ERR_CTX_NULL = 1,
    IPMICONSOLE_ERR_CTX_INVALID = 2,
    IPMICONSOLE_ERR_ALREADY_SETUP = 3,
    IPMICONSOLE_ERR_NOT_SETUP = 4,
    IPMICONSOLE_ERR_CTX_NOT_SUBMITTED = 5,
    IPMICONSOLE_ERR_CTX_IS_SUBMITTED = 6,
    IPMICONSOLE_ERR_PARAMETERS = 7,
    IPMICONSOLE_ERR_HOSTNAME_INVALID = 8,
    IPMICONSOLE_ERR_IPMI_2_0_UNAVAILABLE = 9,
    IPMICONSOLE_ERR_CIPHER_SUITE_ID_UNAVAILABLE = 10,
    IPMICONSOLE_ERR_USERNAME_INVALID = 11,
    IPMICONSOLE_ERR_PASSWORD_INVALID = 12,
    IPMICONSOLE_ERR_K_G_INVALID = 13,
    IPMICONSOLE_ERR_PRIVILEGE_LEVEL_INSUFFICIENT = 14,
    IPMICONSOLE_ERR_PRIVILEGE_LEVEL_CANNOT_BE_OBTAINED = 15,
    IPMICONSOLE_ERR_SOL_UNAVAILABLE = 16,
    IPMICONSOLE_ERR_SOL_INUSE = 17,
    IPMICONSOLE_ERR_SOL_STOLEN = 18,
    IPMICONSOLE_ERR_SOL_REQUIRES_ENCRYPTION = 19,
    IPMICONSOLE_ERR_SOL_REQUIRES_NO_ENCRYPTION = 20,
    IPMICONSOLE_ERR_BMC_BUSY = 21,
    IPMICONSOLE_ERR_BMC_ERROR = 22,
    IPMICONSOLE_ERR_BMC_IMPLEMENTATION = 23,
    IPMICONSOLE_ERR_CONNECTION_TIMEOUT = 24,
    IPMICONSOLE_ERR_SESSION_TIMEOUT = 25,
    IPMICONSOLE_ERR_EXCESS_RETRANSMISSIONS_SENT = 26,
    IPMICONSOLE_ERR_EXCESS_ERRORS_RECEIVED = 27,
    IPMICONSOLE_ERR_OUT_OF_MEMORY = 28,
    IPMICONSOLE_ERR_TOO_MANY_OPEN_FILES = 29,
    IPMICONSOLE_ERR_SYSTEM_ERROR = 30,
    IPMICONSOLE_ERR_INTERNAL_ERROR = 31,
    IPMICONSOLE_ERR_ERRNUMRANGE = 32,
}

#[derive(thiserror::Error, Debug)]
pub enum ipmiconsole_error {
    #[error("ipmiconsole context failed to allocate {0}")]
    ipmiconsole_error_ctx_create(i32),

    #[error("ipmiconsole context is not setup {0}")]
    ipmiconsole_error_ctx_invalid(i32),

    #[error("Failed to open IPMI console session {0}")]
    ipmiconsole_error_conn_fail(i32),

    #[error("Failed to initialize ipmiconsole engine {0}")]
    ipmiconsole_error_eng_init(i32),

    #[error("Failed to retrieve session file descriptor {0}")]
    ipmiconsole_error_fd_invalid(i32),

    #[error("Invalid arguments provided {0}")]
    ipmiconsole_error_invalid_args(i32),

    #[error("Read error on file descriptor {0}")]
    ipmiconsole_error_read_fd(i32),

    #[error("Write error on file descriptor {0}")]
    ipmiconsole_error_write_fd(i32),

    #[error("Failed to send break to the sol session {0}")]
    ipmiconsole_error_send_break(i32),
}

#[repr(u8)]
#[derive(Copy, Clone, IntoPrimitive)]
pub enum privilege_level {
    IPMICONSOLE_PRIVILEGE_USER = 0,
    IPMICONSOLE_PRIVILEGE_OPERATOR = 1,
    IPMICONSOLE_PRIVILEGE_ADMIN = 2,
}

#[repr(u8)]
#[derive(Copy, Clone, IntoPrimitive)] 
/// from Intel Data Center Management Spec 1.1, Table 4-1 Cipher Suite Support.
/// only used for IPMI 2.0 (-I lanplus on ipmitool)
pub enum cipher_suite {
    IPMI_CIPHER_HMAC_SHA1_AES_CBC_128 = 3,
    IPMI_CIPHER_HMAC_MD5_AES_CBC_128 = 8,
    IPMI_CIPHER_HMAC_SHA256_AES_CBC_128 = 17,
}

#[repr(u8)]
#[derive(Copy, Clone, IntoPrimitive)]
/// Used only on IPMI LAN 1.5 (-I lan on ipmitool)
pub enum auth_type {
    IPMI_AUTHENTICATION_TYPE_NONE = 0x00,
    IPMI_AUTHENTICATION_TYPE_MD2 = 0x01,
    IPMI_AUTHENTICATION_TYPE_MD5 = 0x02,
    IPMI_AUTHENTICATION_TYPE_STRAIGHT_PASSWORD_KEY = 0x04,
    IPMI_AUTHENTICATION_TYPE_OEM_PROP = 0x05,
    IPMI_AUTHENTICATION_TYPE_RMCPPLUS = 0x06,
}

#[repr(u8)]
#[derive(Copy, Clone, IntoPrimitive)]
pub enum ipmiconsole_ctx_config_option
{
    IPMICONSOLE_CTX_CONFIG_OPTION_SOL_PAYLOAD_INSTANCE = 0,
}

#[repr(i32)]
#[derive(Copy, Clone, IntoPrimitive)]
pub enum ipmiconsole_status
{
    IPMICONSOLE_CTX_STATUS_ERROR = -1,
    IPMICONSOLE_CTX_STATUS_NOT_SUBMITTED = 0,
    IPMICONSOLE_CTX_STATUS_SUBMITTED = 1,
    IPMICONSOLE_CTX_STATUS_SOL_ERROR = 2,
    IPMICONSOLE_CTX_STATUS_SOL_ESTABLISHED = 3,
}

/* refer ipmiconsole.h for usage of flags */
const IPMICONSOLE_DEBUG_STDOUT: u32 = 0x00000001;
const IPMICONSOLE_DEBUG_STDERR: u32 = 0x00000002;
const IPMICONSOLE_DEBUG_SYSLOG: u32 = 0x00000004;
const IPMICONSOLE_DEBUG_FILE: u32 = 0x00000008;
const IPMICONSOLE_DEBUG_IPMI_PACKETS: u32 = 0x00000010;
const IPMICONSOLE_DEBUG_DEFAULT: u32 = 0xFFFFFFFF;

const IPMICONSOLE_WORKAROUND_AUTHENTICATION_CAPABILITIES: u32 = 0x00000001;
const IPMICONSOLE_WORKAROUND_INTEL_2_0_SESSION: u32 = 0x00000002;
const IPMICONSOLE_WORKAROUND_SUPERMICRO_2_0_SESSION: u32 = 0x00000004;
const IPMICONSOLE_WORKAROUND_SUN_2_0_SESSION: u32 = 0x00000008;
const IPMICONSOLE_WORKAROUND_OPEN_SESSION_PRIVILEGE: u32 = 0x00000010;
const IPMICONSOLE_WORKAROUND_NON_EMPTY_INTEGRITY_CHECK_VALUE: u32 = 0x00000020;
const IPMICONSOLE_WORKAROUND_NO_CHECKSUM_CHECK: u32 = 0x00000040;
const IPMICONSOLE_WORKAROUND_SERIAL_ALERTS_DEFERRED: u32 = 0x00000080;
const IPMICONSOLE_WORKAROUND_INCREMENT_SOL_PACKET_SEQUENCE: u32 = 0x00000100;
const IPMICONSOLE_WORKAROUND_IGNORE_SOL_PAYLOAD_SIZE: u32 = 0x01000000;
const IPMICONSOLE_WORKAROUND_IGNORE_SOL_PORT: u32 = 0x02000000;
const IPMICONSOLE_WORKAROUND_SKIP_SOL_ACTIVATION_STATUS: u32 = 0x04000000;
const IPMICONSOLE_WORKAROUND_SKIP_CHANNEL_PAYLOAD_SUPPORT: u32 = 0x08000000;
const IPMICONSOLE_WORKAROUND_DEFAULT: u32 = 0xFFFFFFFF;

const IPMICONSOLE_ENGINE_CLOSE_FD: u32 = 0x00000001;
const IPMICONSOLE_ENGINE_OUTPUT_ON_SOL_ESTABLISHED: u32 = 0x00000002;
const IPMICONSOLE_ENGINE_LOCK_MEMORY: u32 = 0x00000004;
const IPMICONSOLE_ENGINE_SERIAL_KEEPALIVE: u32 = 0x00000008;
const IPMICONSOLE_ENGINE_SERIAL_KEEPALIVE_EMPTY: u32 = 0x00000010;
const IPMICONSOLE_ENGINE_DEFAULT: u32 = 0xFFFFFFFF;

const IPMICONSOLE_BEHAVIOR_ERROR_ON_SOL_INUSE: u32 = 0x00000001;
const IPMICONSOLE_BEHAVIOR_DEACTIVATE_ONLY: u32 = 0x00000002;
const IPMICONSOLE_BEHAVIOR_DEACTIVATE_ALL_INSTANCES: u32 = 0x00000004;
const IPMICONSOLE_BEHAVIOR_DEFAULT: u32 = 0xFFFFFFFF;

#[repr(C)]
pub struct ipmiconsole_ipmi_config {
    username: *mut c_char,
    password: *mut c_char,
    k_g: *mut u8,
    k_g_len: u32,
    privilege_level: i32,
    cipher_suite_id: i32,
    workaround_flags: u32
}

#[repr(C)]
pub struct ipmiconsole_protocol_config {
    session_timeout_len: i32,
    retransmission_timeout_len: i32,
    retransmission_backoff_count: i32,
    keepalive_timeout_len: i32,
    retransmission_keepalive_timeout_len: i32,
    acceptable_packet_errors_count: i32,
    maximum_retransmission_count: i32
}

#[repr(C)]
pub struct ipmiconsole_engine_config {
    engine_flags: u32,
    behavior_flags: u32,
    debug_flags: u32
}

pub type ipmiconsole_ctx_t = *mut c_void;
pub type ipmiconsole_callback = *mut c_void;

#[link(name = "ipmiconsole")]
extern "C" {
    pub fn ipmiconsole_engine_init(thread_count: c_uint, debug_flags: c_uint) -> c_int;
    pub fn ipmiconsole_engine_submit(
        ctx: ipmiconsole_ctx_t, cb: ipmiconsole_callback, cb_arg: *mut c_void);
    pub fn ipmiconsole_engine_submit_block(ctx: ipmiconsole_ctx_t) -> c_int;
    pub fn ipmiconsole_engine_teardown(cleanup_sol_sessions: c_int);
    pub fn ipmiconsole_ctx_create(
        hostname: *const c_char,
        ipmi_config: *mut ipmiconsole_ipmi_config,
        protocol_config: *mut ipmiconsole_protocol_config,
        engine_config: *mut ipmiconsole_engine_config
        ) -> ipmiconsole_ctx_t;
    pub fn ipmiconsole_ctx_set_config(
        ctx: ipmiconsole_ctx_t,
        config_option: ipmiconsole_ctx_config_option,
        config_option_value: *mut c_void) -> c_int;
    pub fn ipmiconsole_ctx_get_config(
        ctx: ipmiconsole_ctx_t,
        config_option: ipmiconsole_ctx_config_option,
        config_option_value: *mut c_void) -> c_int;
    pub fn ipmiconsole_ctx_errnum(ctx: ipmiconsole_ctx_t) -> c_int;
    pub fn ipmiconsole_ctx_strerror(errnum: c_int) -> *const c_char;
    pub fn ipmiconsole_ctx_status(ctx: ipmiconsole_ctx_t) -> c_int;
    pub fn ipmiconsole_ctx_fd(ctx: ipmiconsole_ctx_t) -> c_int;
    pub fn ipmiconsole_ctx_generate_break(ctx: ipmiconsole_ctx_t) -> c_int;
    pub fn ipmiconsole_ctx_destroy(ctx: ipmiconsole_ctx_t);
}

pub mod ipmiconsole {
    use std::os::unix::io::RawFd;
    use std::ptr;
    use libc::{c_int, ssize_t};
    use std::ffi::CString;
    use crate::*;
    use crate::privilege_level::*;
    use crate::auth_type::*;
    use crate::cipher_suite::*;
    use crate::ipmiconsole_errnum::*;
    use crate::ipmiconsole_error::*;
    //use crate::{auth_type, cipher_suite, privilege_level, ipmiconsole_ctx_t, privilege_level::IPMICONSOLE_PRIVILEGE_ADMIN, cipher_suite::IPMI_CIPHER_HMAC_SHA256_AES_CBC_128, auth_type::IPMI_AUTHENTICATION_TYPE_MD5, IPMICONSOLE_BEHAVIOR_DEACTIVATE_ONLY, IPMICONSOLE_ENGINE_SERIAL_KEEPALIVE, ipmiconsole_ctx_create, ipmiconsole_ctx_destroy, ipmiconsole_ctx_fd, ipmiconsole_ctx_generate_break, ipmiconsole_ipmi_config, ipmiconsole_protocol_config, ipmiconsole_engine_config, ipmiconsole_engine_submit_block, ipmiconsole_engine_teardown};

    pub struct ipmiconsole_ctx {
        hostname: String,
        username: String,
        password: String,
        cipher: cipher_suite, /* used for ipmi 2.0 / lanplus */
        level: privilege_level,
        auth_mode: auth_type, /* used for ipmi 1.5 / lan */
        lib_ctx: ipmiconsole_ctx_t,
        fd: RawFd             /* ipmiconsole I/O */
    }

    impl ipmiconsole_ctx {
        pub fn new(
            host: String,
            user: String,
            pass: String,
            algo: Option<cipher_suite>,
            mode: Option<privilege_level>,
            auth: Option<auth_type>,
        ) -> ipmiconsole_ctx {
            ipmiconsole_ctx {
                hostname: host,
                username: user,
                password: pass,
                cipher: algo.unwrap_or(IPMI_CIPHER_HMAC_SHA256_AES_CBC_128),
                level: mode.unwrap_or(IPMICONSOLE_PRIVILEGE_ADMIN),
                auth_mode: auth.unwrap_or(IPMI_AUTHENTICATION_TYPE_MD5),
                lib_ctx: ptr::null_mut(),
                fd: -1
            }
        }

        pub fn destroy(&mut self) {
            unsafe {
                ipmiconsole_engine_teardown(1);
            }
        }

        pub fn connect(&mut self) -> Result<(), ipmiconsole_error> {
            let c_hostname = CString::new(self.hostname.as_str()).unwrap();
            let c_user = CString::new(self.username.as_str()).unwrap();
            let c_pass = CString::new(self.password.as_str()).unwrap();

            let mut cfg = ipmiconsole_ipmi_config {
                username: c_user.into_raw(),
                password: c_pass.into_raw(),
                k_g: ptr::null_mut(),
                k_g_len: 0,
                privilege_level: self.level as i32,
                cipher_suite_id: self.cipher as i32,
                workaround_flags: 0
            };

            let mut proto_cfg = ipmiconsole_protocol_config {
                session_timeout_len: 60000,
                retransmission_timeout_len: 500,
                retransmission_backoff_count: -1,
                keepalive_timeout_len: -1,
                retransmission_keepalive_timeout_len: -1,
                acceptable_packet_errors_count: -1,
                maximum_retransmission_count: -1
            };

            let mut eng_cfg = ipmiconsole_engine_config {
                engine_flags: IPMICONSOLE_ENGINE_SERIAL_KEEPALIVE,
                behavior_flags: IPMICONSOLE_BEHAVIOR_DEACTIVATE_ONLY,
                debug_flags: 0
            };

            unsafe {
                let mut ret: c_int;
                ret = ipmiconsole_engine_init(1, 0);
                if ret < 0 {
                    let err = errno();
                    return Err(ipmiconsole_error::ipmiconsole_error_eng_init(err.into()));
                }

                self.lib_ctx = ipmiconsole_ctx_create(c_hostname.as_ptr(), &mut cfg, &mut proto_cfg, &mut eng_cfg);
                if self.lib_ctx.is_null() {
                    let err = errno();
                    return Err(ipmiconsole_error::ipmiconsole_error_ctx_create(err.into()));
                }

                ret = ipmiconsole_engine_submit_block(self.lib_ctx);
                if ret < 0 {
                    ret = ipmiconsole_ctx_errnum(self.lib_ctx);
                    return Err(ipmiconsole_error::ipmiconsole_error_conn_fail(ret as i32));
                }
                self.fd = ipmiconsole_ctx_fd(self.lib_ctx);
                if self.fd < 0 {
                    ret = ipmiconsole_ctx_errnum(self.lib_ctx);
                    return Err(ipmiconsole_error::ipmiconsole_error_fd_invalid(ret as i32));
                }
            }

            Ok(())
        }

        pub fn disconnect(&mut self) -> Result<(), ipmiconsole_error> {
            if self.lib_ctx.is_null() {
                return Err(ipmiconsole_error::ipmiconsole_error_ctx_invalid(
                    IPMICONSOLE_ERR_CTX_INVALID as i32));
            }
            unsafe {
                if self.fd >= 0 {
                    libc::close(self.fd);
                }
                ipmiconsole_ctx_destroy(self.lib_ctx);
            }
            Ok(())
        }

        /// read from the sol fd to given buffer. short reads may occur, caller needs to handle.
        pub fn read(&mut self, buf: &mut [u8]) -> Result<ssize_t, ipmiconsole_error> {
            if self.fd < 0 {
                return Err(ipmiconsole_error::ipmiconsole_error_ctx_invalid(
                    IPMICONSOLE_ERR_CTX_INVALID as i32));
            }
            if buf.len() >= isize::MAX as usize {
                return Err(ipmiconsole_error::ipmiconsole_error_invalid_args(
                    IPMICONSOLE_ERR_PARAMETERS as i32));
            }
            unsafe {
                let ret = libc::read(self.fd, buf.as_mut_ptr() as _, buf.len());
                if ret < 0 {
                    let err = errno();
                    return Err(ipmiconsole_error::ipmiconsole_error_read_fd(err.into()));
                }
                return Ok(ret);
            }
        }

        /// write to sol fd from the given buffer. short writes may occur, caller needs to handle.
        pub fn write(&mut self, buf: &mut [u8]) -> Result<ssize_t, ipmiconsole_error> {
            if self.fd < 0 {
                return Err(ipmiconsole_error::ipmiconsole_error_ctx_invalid(
                    IPMICONSOLE_ERR_CTX_INVALID as i32));
            }
            if buf.len() >= isize::MAX as usize {
                return Err(ipmiconsole_error::ipmiconsole_error_invalid_args(
                    IPMICONSOLE_ERR_PARAMETERS as i32));
            }
            unsafe {
                let ret = libc::write(self.fd, buf.as_mut_ptr() as _, buf.len());
                if ret < 0 {
                    let err = errno();
                    return Err(ipmiconsole_error::ipmiconsole_error_read_fd(err.into()));
                }
                return Ok(ret);
            }
        }

        pub fn send_break(&mut self) -> Result<(), ipmiconsole_error> {
            if self.lib_ctx.is_null() {
                return Err(ipmiconsole_error::ipmiconsole_error_ctx_invalid(
                    IPMICONSOLE_ERR_CTX_INVALID as i32));
            }
            unsafe {
                let mut ret: c_int = ipmiconsole_ctx_generate_break(self.lib_ctx);
                if ret != 0 {
                    ret = ipmiconsole_ctx_errnum(self.lib_ctx);
                    return Err(ipmiconsole_error::ipmiconsole_error_send_break(ret as i32));
                }
            }
            Ok(())
        }

    }
}
