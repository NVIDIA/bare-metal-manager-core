// WARNING: libipmiconsole is GPLv3!
// Including libipmiconsole headers directly probably means using its sources and creating a derived
// work.

use libc::{c_char, c_int, c_uint, c_void};
use num_enum::IntoPrimitive;

#[cfg(feature = "libc")]
// relevant enums from the c headers
#[repr(u8)]
#[derive(Copy, Clone, IntoPrimitive)]
/// Errors from libipmiconsole
pub enum IpmiConsoleErrorKind {
    Success = 0,
    Null = 1,
    ContextInvalid = 2,
    AlreadySetup = 3,
    NotSetup = 4,
    NotSubmitted = 5,
    ContextIsSubmitted = 6,
    Parameters = 7,
    HostnameInvalid = 8,
    Ipmi2_0Unavailable = 9,
    CipherSuiteIdUnavailable = 10,
    UsernameInvalid = 11,
    PasswordInvalid = 12,
    KgInvalid = 13,
    PrivilegeLevelInsufficient = 14,
    PrivilegeLevelCannotBeObtained = 15,
    SolUnavailable = 16,
    SolInuse = 17,
    SolStolen = 18,
    SolRequiresEncryption = 19,
    SolRequiresNoEncryption = 20,
    BmcBusy = 21,
    BmcError = 22,
    BmcImplementation = 23,
    ConnectionTimeout = 24,
    SessionTimeout = 25,
    ExcessRetransmissionsSent = 26,
    ExcessErrorsReceived = 27,
    OutOfMemory = 28,
    TooManyOpenFiles = 29,
    SystemError = 30,
    InternalError = 31,
    ErrNumRange = 32,
}

//Ron: this generally appears to be mis-modelled: most of the integers are just a flat mapping
//from the status code, but we no longer need the mapping once the error is constructed?
//I believe that the correct model is one where unless multiple different error codes can come
//from on "kind", all of the integers should "go away" from this type
#[derive(thiserror::Error, Debug)]
pub enum IpmiConsoleError {
    #[error("ipmiconsole context failed to allocate {0}")]
    ContextCreate(i32),

    #[error("ipmiconsole context is not setup {0}")]
    ContextInvalid(i32),

    #[error("Failed to open IPMI console session {0}")]
    ConnectionFail(i32),

    #[error("Failed to initialize ipmiconsole engine {0}")]
    EngInit(i32),

    #[error("Failed to retrieve session file descriptor {0}")]
    FdInvalid(i32),

    #[error("Invalid arguments provided {0}")]
    InvalidArgs(i32),

    #[error("Read error on file descriptor {0}")]
    ReadFd(i32),

    #[error("Write error on file descriptor {0}")]
    WriteFd(i32),

    #[error("Failed to send break to the sol session {0}")]
    SendBreak(i32),
}

#[repr(u8)]
#[derive(Copy, Clone, IntoPrimitive)]
pub enum PrivilegeLevel {
    User = 0,
    Operator = 1,
    Admin = 2,
}

#[repr(u8)]
#[derive(Copy, Clone, IntoPrimitive)]
/// from Intel Data Center Management Spec 1.1, Table 4-1 Cipher Suite Support.
/// only used for IPMI 2.0 (-I lanplus on ipmitool)
pub enum CipherSuite {
    HmacSha1AesCbc128 = 3,
    HmacMd5AesCbc128 = 8,
    HmacSha256AesCbc128 = 17,
}

#[repr(u8)]
#[derive(Copy, Clone, IntoPrimitive)]
/// Used only on IPMI LAN 1.5 (-I lan on ipmitool)
pub enum AuthenticationType {
    None = 0x00,
    Md2 = 0x01,
    Md5 = 0x02,
    StraightPasswordKey = 0x04,
    OemProp = 0x05,
    RmcpPlus = 0x06,
}

#[repr(u8)]
#[derive(Copy, Clone, IntoPrimitive)]
pub enum IpmiConsoleContextConfigOption {
    SolPayloadInstance = 0,
}

#[repr(i32)]
#[derive(Copy, Clone, IntoPrimitive)]
pub enum IpmiConsoleContextStatus {
    Error = -1,
    NotSubmitted = 0,
    Submitted = 1,
    SolError = 2,
    SolEstablished = 3,
}

#[repr(C)]
pub struct IpmiConsoleIpmiConfig {
    username: *mut c_char,
    password: *mut c_char,
    k_g: *mut u8,
    k_g_len: u32,
    privilege_level: i32,
    cipher_suite_id: i32,
    workaround_flags: u32,
}

#[repr(C)]
pub struct IpmiConsoleProtocolConfig {
    session_timeout_len: i32,
    retransmission_timeout_len: i32,
    retransmission_backoff_count: i32,
    keepalive_timeout_len: i32,
    retransmission_keepalive_timeout_len: i32,
    acceptable_packet_errors_count: i32,
    maximum_retransmission_count: i32,
}

#[repr(C)]
pub struct IpmiConsoleEngineConfig {
    engine_flags: u32,
    behavior_flags: u32,
    debug_flags: u32,
}

pub type IpmiConsoleContextType = *mut c_void;
pub type IpmiConsoleCallbackType = *mut c_void;

#[link(name = "ipmiconsole")]
extern "C" {
    pub fn ipmiconsole_engine_init(thread_count: c_uint, debug_flags: c_uint) -> c_int;
    pub fn ipmiconsole_engine_submit(
        ctx: IpmiConsoleContextType,
        cb: IpmiConsoleCallbackType,
        cb_arg: *mut c_void,
    );
    pub fn ipmiconsole_engine_submit_block(ctx: IpmiConsoleContextType) -> c_int;
    pub fn ipmiconsole_engine_teardown(cleanup_sol_sessions: c_int);
    pub fn ipmiconsole_ctx_create(
        hostname: *const c_char,
        ipmi_config: *mut IpmiConsoleIpmiConfig,
        protocol_config: *mut IpmiConsoleProtocolConfig,
        engine_config: *mut IpmiConsoleEngineConfig,
    ) -> IpmiConsoleContextType;
    pub fn ipmiconsole_ctx_set_config(
        ctx: IpmiConsoleContextType,
        config_option: IpmiConsoleContextConfigOption,
        config_option_value: *mut c_void,
    ) -> c_int;
    pub fn ipmiconsole_ctx_get_config(
        ctx: IpmiConsoleContextType,
        config_option: IpmiConsoleContextConfigOption,
        config_option_value: *mut c_void,
    ) -> c_int;
    pub fn ipmiconsole_ctx_errnum(ctx: IpmiConsoleContextType) -> c_int;
    pub fn ipmiconsole_ctx_strerror(errnum: c_int) -> *const c_char;
    pub fn ipmiconsole_ctx_status(ctx: IpmiConsoleContextType) -> c_int;
    pub fn ipmiconsole_ctx_fd(ctx: IpmiConsoleContextType) -> c_int;
    pub fn ipmiconsole_ctx_generate_break(ctx: IpmiConsoleContextType) -> c_int;
    pub fn ipmiconsole_ctx_destroy(ctx: IpmiConsoleContextType);
}

mod ipmi_console_constants {
    /* refer ipmiconsole.h for usage of flags */
    //TODO: as these flags start to actually be referenced, remove the leading underscore.
    pub const _IPMI_CONSOLE_DEBUG_STDOUT: u32 = 0x00000001;
    pub const _IPMI_CONSOLE_DEBUG_STDERR: u32 = 0x00000002;
    pub const _IPMI_CONSOLE_DEBUG_SYSLOG: u32 = 0x00000004;
    pub const _IPMI_CONSOLE_DEBUG_FILE: u32 = 0x00000008;
    pub const _IPMI_CONSOLE_DEBUG_IPMI_PACKETS: u32 = 0x00000010;
    pub const _IPMI_CONSOLE_DEBUG_DEFAULT: u32 = 0xFFFFFFFF;

    pub const _IPMI_CONSOLE_WORKAROUND_AUTHENTICATION_CAPABILITIES: u32 = 0x00000001;
    pub const _IPMI_CONSOLE_WORKAROUND_INTEL_2_0_SESSION: u32 = 0x00000002;
    pub const _IPMI_CONSOLE_WORKAROUND_SUPERMICRO_2_0_SESSION: u32 = 0x00000004;
    pub const _IPMI_CONSOLE_WORKAROUND_SUN_2_0_SESSION: u32 = 0x00000008;
    pub const _IPMI_CONSOLE_WORKAROUND_OPEN_SESSION_PRIVILEGE: u32 = 0x00000010;
    pub const _IPMI_CONSOLE_WORKAROUND_NON_EMPTY_INTEGRITY_CHECK_VALUE: u32 = 0x00000020;
    pub const _IPMI_CONSOLE_WORKAROUND_NO_CHECKSUM_CHECK: u32 = 0x00000040;
    pub const _IPMI_CONSOLE_WORKAROUND_SERIAL_ALERTS_DEFERRED: u32 = 0x00000080;
    pub const _IPMI_CONSOLE_WORKAROUND_INCREMENT_SOL_PACKET_SEQUENCE: u32 = 0x00000100;
    pub const _IPMI_CONSOLE_WORKAROUND_IGNORE_SOL_PAYLOAD_SIZE: u32 = 0x01000000;
    pub const _IPMI_CONSOLE_WORKAROUND_IGNORE_SOL_PORT: u32 = 0x02000000;
    pub const _IPMI_CONSOLE_WORKAROUND_SKIP_SOL_ACTIVATION_STATUS: u32 = 0x04000000;
    pub const _IPMI_CONSOLE_WORKAROUND_SKIP_CHANNEL_PAYLOAD_SUPPORT: u32 = 0x08000000;
    pub const _IPMI_CONSOLE_WORKAROUND_DEFAULT: u32 = 0xFFFFFFFF;
    pub const _IPMI_CONSOLE_ENGINE_CLOSE_FD: u32 = 0x00000001;
    pub const _IPMI_CONSOLE_ENGINE_OUTPUT_ON_SOL_ESTABLISHED: u32 = 0x00000002;
    pub const _IPMI_CONSOLE_ENGINE_LOCK_MEMORY: u32 = 0x00000004;

    pub const IPMI_CONSOLE_ENGINE_SERIAL_KEEPALIVE: u32 = 0x00000008;

    pub const _IPMI_CONSOLE_ENGINE_SERIAL_KEEPALIVE_EMPTY: u32 = 0x00000010;
    pub const _IPMI_CONSOLE_ENGINE_DEFAULT: u32 = 0xFFFFFFFF;

    pub const _IPMI_CONSOLE_BEHAVIOR_ERROR_ON_SOL_INUSE: u32 = 0x00000001;
    pub const IPMI_CONSOLE_BEHAVIOR_DEACTIVATE_ONLY: u32 = 0x00000002;
    pub const _IPMI_CONSOLE_BEHAVIOR_DEACTIVATE_ALL_INSTANCES: u32 = 0x00000004;
    pub const _IPMI_CONSOLE_BEHAVIOR_DEFAULT: u32 = 0xFFFFFFFF;
}

pub mod ipmi_console {
    use std::ffi::CString;
    use std::os::unix::io::RawFd;
    use std::ptr;

    use errno::errno;
    use libc::{c_int, ssize_t};

    use crate::{
        ipmi_console_constants, ipmiconsole_ctx_create, ipmiconsole_ctx_destroy,
        ipmiconsole_ctx_errnum, ipmiconsole_ctx_fd, ipmiconsole_ctx_generate_break,
        ipmiconsole_engine_init, ipmiconsole_engine_submit_block, ipmiconsole_engine_teardown,
        AuthenticationType, CipherSuite, IpmiConsoleContextType, IpmiConsoleEngineConfig,
        IpmiConsoleError, IpmiConsoleErrorKind, IpmiConsoleIpmiConfig, IpmiConsoleProtocolConfig,
        PrivilegeLevel,
    };

    pub struct IpmiConsoleContext {
        hostname: String,
        username: String,
        password: String,
        cipher: CipherSuite,
        /* used for ipmi 2.0 / lanplus */
        level: PrivilegeLevel,
        _auth_mode: AuthenticationType,
        /* used for ipmi 1.5 / lan */
        lib_ctx: IpmiConsoleContextType,
        fd: RawFd,
        /* ipmiconsole I/O */
    }

    impl IpmiConsoleContext {
        pub fn new(
            host: String,
            user: String,
            pass: String,
            algo: Option<CipherSuite>,
            mode: Option<PrivilegeLevel>,
            auth: Option<AuthenticationType>,
        ) -> Self {
            Self {
                hostname: host,
                username: user,
                password: pass,
                cipher: algo.unwrap_or(CipherSuite::HmacSha256AesCbc128),
                level: mode.unwrap_or(PrivilegeLevel::Admin),
                _auth_mode: auth.unwrap_or(AuthenticationType::Md5),
                lib_ctx: ptr::null_mut(),
                fd: -1,
            }
        }

        pub fn destroy(&mut self) {
            unsafe {
                ipmiconsole_engine_teardown(1);
            }
        }

        pub fn connect(&mut self) -> Result<(), IpmiConsoleError> {
            let c_hostname = CString::new(self.hostname.as_str()).unwrap();
            let c_user = CString::new(self.username.as_str()).unwrap();
            let c_pass = CString::new(self.password.as_str()).unwrap();

            let mut cfg = IpmiConsoleIpmiConfig {
                username: c_user.into_raw(),
                password: c_pass.into_raw(),
                k_g: ptr::null_mut(),
                k_g_len: 0,
                privilege_level: self.level as i32,
                cipher_suite_id: self.cipher as i32,
                workaround_flags: 0,
            };

            let mut proto_cfg = IpmiConsoleProtocolConfig {
                session_timeout_len: 60000,
                retransmission_timeout_len: 500,
                retransmission_backoff_count: -1,
                keepalive_timeout_len: -1,
                retransmission_keepalive_timeout_len: -1,
                acceptable_packet_errors_count: -1,
                maximum_retransmission_count: -1,
            };

            let mut eng_cfg = IpmiConsoleEngineConfig {
                engine_flags: ipmi_console_constants::IPMI_CONSOLE_ENGINE_SERIAL_KEEPALIVE,
                behavior_flags: ipmi_console_constants::IPMI_CONSOLE_BEHAVIOR_DEACTIVATE_ONLY,
                debug_flags: 0,
            };

            unsafe {
                let mut ret: c_int;
                ret = ipmiconsole_engine_init(1, 0);
                if ret < 0 {
                    let err = errno();
                    return Err(IpmiConsoleError::EngInit(err.into()));
                }

                self.lib_ctx = ipmiconsole_ctx_create(
                    c_hostname.as_ptr(),
                    &mut cfg,
                    &mut proto_cfg,
                    &mut eng_cfg,
                );
                if self.lib_ctx.is_null() {
                    let err = errno();
                    return Err(IpmiConsoleError::ContextCreate(err.into()));
                }

                ret = ipmiconsole_engine_submit_block(self.lib_ctx);
                if ret < 0 {
                    ret = ipmiconsole_ctx_errnum(self.lib_ctx);
                    return Err(IpmiConsoleError::ConnectionFail(ret as i32));
                }
                self.fd = ipmiconsole_ctx_fd(self.lib_ctx);
                if self.fd < 0 {
                    ret = ipmiconsole_ctx_errnum(self.lib_ctx);
                    return Err(IpmiConsoleError::FdInvalid(ret as i32));
                }
            }

            Ok(())
        }

        pub fn disconnect(&mut self) -> Result<(), IpmiConsoleError> {
            if self.lib_ctx.is_null() {
                return Err(IpmiConsoleError::ContextInvalid(
                    IpmiConsoleErrorKind::ContextInvalid as i32,
                ));
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
        pub fn read(&mut self, buf: &mut [u8]) -> Result<ssize_t, IpmiConsoleError> {
            if self.fd < 0 {
                return Err(IpmiConsoleError::ContextInvalid(
                    IpmiConsoleErrorKind::ContextInvalid as i32,
                ));
            }
            if buf.len() >= isize::MAX as usize {
                return Err(IpmiConsoleError::InvalidArgs(
                    IpmiConsoleErrorKind::Parameters as i32,
                ));
            }
            unsafe {
                let ret = libc::read(self.fd, buf.as_mut_ptr() as _, buf.len());
                if ret < 0 {
                    let err = errno();
                    return Err(IpmiConsoleError::ReadFd(err.into()));
                }
                Ok(ret)
            }
        }

        /// write to sol fd from the given buffer. short writes may occur, caller needs to handle.
        pub fn write(&mut self, buf: &mut [u8]) -> Result<ssize_t, IpmiConsoleError> {
            if self.fd < 0 {
                return Err(IpmiConsoleError::ContextInvalid(
                    IpmiConsoleErrorKind::ContextInvalid as i32,
                ));
            }
            if buf.len() >= isize::MAX as usize {
                return Err(IpmiConsoleError::InvalidArgs(
                    IpmiConsoleErrorKind::Parameters as i32,
                ));
            }
            unsafe {
                let ret = libc::write(self.fd, buf.as_mut_ptr() as _, buf.len());
                if ret < 0 {
                    let err = errno();
                    return Err(IpmiConsoleError::ReadFd(err.into()));
                }
                Ok(ret)
            }
        }

        pub fn send_break(&mut self) -> Result<(), IpmiConsoleError> {
            if self.lib_ctx.is_null() {
                return Err(IpmiConsoleError::ContextInvalid(
                    IpmiConsoleErrorKind::ContextInvalid as i32,
                ));
            }
            unsafe {
                let mut ret: c_int = ipmiconsole_ctx_generate_break(self.lib_ctx);
                if ret != 0 {
                    ret = ipmiconsole_ctx_errnum(self.lib_ctx);
                    return Err(IpmiConsoleError::SendBreak(ret as i32));
                }
            }
            Ok(())
        }
    }
}
