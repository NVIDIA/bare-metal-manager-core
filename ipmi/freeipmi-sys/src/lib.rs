/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2022 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */
// WARNING: libfreeipmi is GPLv3!
// Including libfreeipmi headers directly probably means using its sources and creating a derived
// work.

use std::os::raw::{c_char, c_int, c_uchar, c_uint, c_void};

use libc::c_ulonglong;
use libc::c_ushort;
use num_enum::IntoPrimitive;
use serde::{Deserialize, Serialize};

#[cfg(feature = "libc")]
// relevant enums from the c headers
#[repr(u8)]
#[derive(Copy, Clone, IntoPrimitive)]
/// IPMI interface types, currently only IPMI_DEVICE_LAN and IPMI_DEVICE_LAN_2_0 are supported.
pub enum IpmiDevice {
    Unknown = 0,
    Lan = 1,
    Lan2_0 = 2,
    Kcs = 3,
    Smic = 4,
    Bt = 5,
    Ssif = 6,
    OpenIpmi = 7,
    SunBmc = 8,
    IntelDcmi = 9,
}

#[repr(u8)]
#[derive(Copy, Clone, IntoPrimitive)]
/// from Intel Data Center Management Spec 1.1, Table 4-1 Cipher Suite Support.
/// only used for IPMI 2.0 (-I lanplus on ipmitool)
pub enum IpmiCipherSuite {
    HmacSha1AesCbc128 = 3,
    HmacMd5AesCbc128 = 8,
    HmacSha256AesCbc128 = 17,
}

#[repr(u8)]
#[derive(Copy, Clone, IntoPrimitive)]
pub enum IpmiPrivilegeLevel {
    Reserved = 0x00,
    /* IPMI_PRIVILEGE_LEVEL_HIGHEST_LEVEL(u8)  = 0x00, IPMI 2.0 */
    /* IPMI_PRIVILEGE_LEVEL_UNSPECIFIED(u8)    = 0x00, RMCP+ Cipher Suite Priv Config */
    Callback = 0x01,
    User = 0x02,
    Operator = 0x03,
    Admin = 0x04,
    Oem = 0x05,
    NoAccess = 0x0F,
}

#[repr(u8)]
#[derive(Copy, Clone, IntoPrimitive)]
/// Used only on IPMI LAN 1.5 (-I lan on ipmitool)
pub enum IpmiAuthenticationType {
    None = 0x00,
    Md2 = 0x01,
    Md5 = 0x02,
    StraightPasswordKey = 0x04,
    OemProp = 0x05,
    RmcpPlus = 0x06,
}

#[repr(u8)]
#[derive(Copy, Clone, IntoPrimitive)]
/// Errors that libfreeipmi typically returns
pub enum IpmiErrorNum {
    Success = 0,
    ContextNull = 1,
    ContextInvalid = 2,
    Permission = 3,
    UsernameInvalid = 4,
    PasswordInvalid = 5,
    KgInvalid = 6,
    PrivilegeLevelInsufficient = 7,
    PrivilegeLevelCannotBeObtained = 8,
    AuthenticationTypeUnavailable = 9,
    CipherSuiteIdUnavailable = 10,
    PasswordVerificationTimeout = 11,
    Ipmi2_0Unavailable = 12,
    ConnectionTimeout = 13,
    SessionTimeout = 14,
    DeviceAlreadyOpen = 15,
    DeviceNotOpen = 16,
    DeviceNotSupported = 17,
    DeviceNotFound = 18,
    DriverBusy = 19,
    DriverTimeout = 20,
    MessageTimeout = 21,
    CommandInvalidForSelectedInterface = 22,
    CommandInvalidOrUnsupported = 23,
    BadCompletionCode = 24,
    BadRmcpPlusStatusCode = 25,
    NotFound = 26,
    BmcBusy = 27,
    OutOfMemory = 28,
    HostnameInvalid = 29,
    Parameters = 30,
    DriverPathRequired = 31,
    IpmiError = 32,
    SystemError = 33,
    InternalError = 34,
    ErrNumRange = 35,
}

#[derive(thiserror::Error, Debug)]
pub enum IpmiError {
    #[error("freeipmi context not allocated {0}")]
    ContextInvalid(i32),

    #[error("Failed to open IPMI session {0}")]
    ConnectionFail(i32),

    #[error("Failed to set chassis power control {0}")]
    PowerControlFail(i32),

    #[error("Failed to allocate internal api object for chassis status {0}")]
    FiidObjectAllocate(i32),

    #[error("Failed to query chassis status {0}")]
    ChassisStatus(i32),

    #[error("Failed to query internal api object for chassis status item {0}")]
    FiidQuery(String, i32),
}

#[repr(u8)]
#[derive(Copy, Clone, IntoPrimitive)]
/// Power restore policy that is returned by querying chassis status
pub enum PowerRestorePolicyState {
    PoweredOffAfterAcReturns = 0x00,
    PowerRestoredToState = 0x01,
    PowersUpAfterAcReturns = 0x02,
    Unknown = 0x03,
}

#[repr(u8)]
#[derive(Copy, Clone, IntoPrimitive)]
pub enum PowerRestorePolicySet {
    AlwaysStayPoweredOff = 0x00,
    RestorePowerToStateWhenAcWasLost = 0x01,
    AlwaysPowerUpAfterAcWasLost = 0x02,
    NoChange = 0x03,
}

#[repr(u8)]
#[derive(Copy, Clone, IntoPrimitive)]
pub enum IpmiSystemPowerState {
    Off = 0,
    On = 1,
}

#[repr(u8)]
#[derive(Copy, Clone, IntoPrimitive)]
pub enum IpmiLastPowerEvent {
    AcFailed = 0x00,
    PowerDownPowerOverload = 0x01,
    PowerDownInterlockActivated = 0x02,
    PowerDownPowerFault = 0x03,
    PowerOnViaIpmi = 0x04,
    Unknown = 0x05,
}

#[repr(u8)]
#[derive(Copy, Clone, Serialize, Deserialize, IntoPrimitive, Debug)]
pub enum IpmiChassisControl {
    PowerDown = 0x00,
    PowerUp = 0x01,
    PowerCycle = 0x02,
    HardReset = 0x03,
    PulseDiagnosticInterrupt = 0x04,
    InitiateSoftShutdown = 0x05,
}

#[repr(u8)]
#[derive(Copy, Clone, IntoPrimitive)]
pub enum IpmiChassisForceIdentify {
    Off = 0x00,
    On = 0x01,
}

#[repr(u8)]
#[derive(Copy, Clone, IntoPrimitive)]
pub enum IpmiChassisIdentifyState {
    Off = 0x00,
    TemporarilyOn = 0x01,
    IndefinitelyOn = 0x02,
}

#[repr(u8)]
#[derive(Copy, Clone, IntoPrimitive)]
pub enum IpmiChassisSystemRestartCause {
    Unknown = 0x00,
    ChassisControlCommand = 0x01,
    ResetViaPushbutton = 0x02,
    PowerUpViaPushbutton = 0x03,
    WatchdogExpiration = 0x04,
    Oem = 0x05,
    AutomaticPowerUpAlwaysRestore = 0x06,
    AutomaticPowerUpRestorePrevious = 0x07,
    ResetViaPef = 0x08,
    PowerCycleViaPef = 0x09,
    SoftReset = 0x0A,
    PowerUpViaRtc = 0x0B,
}

/// freeipmi api context to pass the opaque library ptr around.
pub type IpmiContextType = *mut c_void;
/// freeipmi fiid api context to pass the opaque library ptr around.
pub type FiidObj = *mut c_void; /* define as struct fiid_obj later */
/// freeipmi fiid api context to pass the opaque library ptr around.
pub type FiidTemplate = c_void;
/// freeipmi fiid api context to pass the opaque library ptr around.
pub type FiidHash = *mut c_void;

/// typedefs from the c headers
pub type IpmiDriver = IpmiDevice;
pub type IpmiErrorType = IpmiErrorNum;

#[link(name = "freeipmi")]
extern "C" {
    /// static fiid api globals from libfreeipmi for chassis cmds in ipmi-chassis-cmds.h
    #[link_name = "tmpl_cmd_get_chassis_capabilities_rq"]
    pub static tmpl_cmd_get_chassis_capabilities_rq: FiidTemplate;

    #[link_name = "tmpl_cmd_get_chassis_capabilities_rs"]
    pub static tmpl_cmd_get_chassis_capabilities_rs: FiidTemplate;

    #[link_name = "tmpl_cmd_get_chassis_status_rq"]
    pub static tmpl_cmd_get_chassis_status_rq: FiidTemplate;

    #[link_name = "tmpl_cmd_get_chassis_status_rs"]
    pub static tmpl_cmd_get_chassis_status_rs: FiidTemplate;

    #[link_name = "tmpl_cmd_chassis_control_rq"]
    pub static tmpl_cmd_chassis_control_rq: FiidTemplate;

    #[link_name = "tmpl_cmd_chassis_control_rs"]
    pub static tmpl_cmd_chassis_control_rs: FiidTemplate;

    #[link_name = "tmpl_cmd_chassis_identify_rq"]
    pub static tmpl_cmd_chassis_identify_rq: FiidTemplate;

    #[link_name = "tmpl_cmd_chassis_identify_rs"]
    pub static tmpl_cmd_chassis_identify_rs: FiidTemplate;

    #[link_name = "tmpl_cmd_set_power_restore_policy_rq"]
    pub static tmpl_cmd_set_power_restore_policy_rq: FiidTemplate;

    #[link_name = "tmpl_cmd_set_power_restore_policy_rs"]
    pub static tmpl_cmd_set_power_restore_policy_rs: FiidTemplate;

    #[link_name = "tmpl_cmd_set_power_cycle_interval_rq"]
    pub static tmpl_cmd_set_power_cycle_interval_rq: FiidTemplate;

    #[link_name = "tmpl_cmd_set_power_cycle_interval_rs"]
    pub static tmpl_cmd_set_power_cycle_interval_rs: FiidTemplate;

    #[link_name = "tmpl_cmd_get_system_restart_cause_rq"]
    pub static tmpl_cmd_get_system_restart_cause_rq: FiidTemplate;

    #[link_name = "tmpl_cmd_get_system_restart_cause_rs"]
    pub static tmpl_cmd_get_system_restart_cause_rs: FiidTemplate;

    #[link_name = "tmpl_cmd_set_system_boot_options_rq"]
    pub static tmpl_cmd_set_system_boot_options_rq: FiidTemplate;

    #[link_name = "tmpl_cmd_set_system_boot_options_rs"]
    pub static tmpl_cmd_set_system_boot_options_rs: FiidTemplate;

    #[link_name = "tmpl_cmd_get_system_boot_options_rq"]
    pub static tmpl_cmd_get_system_boot_options_rq: FiidTemplate;

    #[link_name = "tmpl_cmd_get_system_boot_options_rs"]
    pub static tmpl_cmd_get_system_boot_options_rs: FiidTemplate;

    #[link_name = "tmpl_cmd_get_power_on_hours_counter_rq"]
    pub static tmpl_cmd_get_power_on_hours_counter_rq: FiidTemplate;

    #[link_name = "tmpl_cmd_get_power_on_hours_counter_rs"]
    pub static tmpl_cmd_get_power_on_hours_counter_rs: FiidTemplate;
}

// Functions
#[link(name = "freeipmi")] /* link to existing installed libfreeipmi on build host */
extern "C" {
    // api/ipmi-api.h functions:
    // these are the starting point for establishing an ipmi session to run ipmi commands

    /// Inner libfreeipmi C unsafe API - context creation
    pub fn ipmi_ctx_create() -> IpmiContextType;
    /// Inner libfreeipmi C unsafe API - error retrieval
    pub fn ipmi_ctx_errnum(ctx: IpmiContextType) -> c_int;
    /// Inner libfreeipmi C unsafe API - error retrieval
    pub fn ipmi_ctx_strerror(errnum: c_int) -> *mut c_char;
    /// Inner libfreeipmi C unsafe API - error retrieval
    pub fn ipmi_ctx_errormsg(ctx: IpmiContextType) -> *mut c_char;
    /// Inner libfreeipmi C unsafe API - get context flags
    pub fn ipmi_ctx_get_flags(ctx: IpmiContextType, flags: *mut c_uint) -> c_int;
    /// Inner libfreeipmi C unsafe API - set context flags
    pub fn ipmi_ctx_set_flags(ctx: IpmiContextType, flags: c_uint) -> c_int; // use with care
    /// Inner libfreeipmi C unsafe API - setup IPMI 1.5 lan session
    pub fn ipmi_ctx_open_outofband(
        ctx: IpmiContextType,
        hostname: *const c_char,
        username: *const c_char,
        password: *const c_char,
        authentication_type: c_uchar,
        privilege_level: c_uchar,
        session_timeout: c_uint,
        retransmission_timeout: c_uint,
        workaround_flags: c_uint,
        flags: c_uint,
    ) -> c_int;

    /// Inner libfreeipmi C unsafe API - setup IPMI 2.0 lanplus session
    pub fn ipmi_ctx_open_outofband_2_0(
        ctx: IpmiContextType,
        hostname: *const c_char,
        username: *const c_char,
        password: *const c_char,
        k_g: *const c_uchar,
        k_g_len: c_uint,
        privilege_level: c_uchar,
        cipher_suite_id: c_uchar,
        session_timeout: c_uint,
        retransmission_timeout: c_uint,
        workaround_flags: c_uint,
        flags: c_uint,
    ) -> c_int;

    /// Inner libfreeipmi C unsafe API - setup IPMI inband (local BMC) session
    pub fn ipmi_ctx_open_inband(
        ctx: IpmiContextType,
        driver_type: IpmiDriver,
        disable_auto_probe: c_int,
        driver_address: c_ushort,
        register_spacing: c_uchar,
        driver_device: *const c_char,
        workaround_flags: c_uint,
        flags: c_uint,
    ) -> c_int;
    /// Inner libfreeipmi C unsafe API - Probe IPMI inband (local BMC)
    // return 1 on driver found, 0 on not found, -1 on error
    // if specified, driver type returned in driver_type
    pub fn ipmi_ctx_find_inband(
        ctx: IpmiContextType,
        driver_type: IpmiDriver,
        disable_auto_probe: c_int,
        driver_address: c_ushort,
        register_spacing: c_uchar,
        driver_device: *const c_char,
        workaround_flags: c_uint,
        flags: c_uint,
    ) -> c_int;

    /// Inner libfreeipmi C unsafe API - close session
    pub fn ipmi_ctx_close(ctx: IpmiContextType) -> c_int;
    /// Inner libfreeipmi C unsafe API - cleanup context
    pub fn ipmi_ctx_destroy(ctx: IpmiContextType);
    /// Inner libfreeipmi C unsafe API - send ipmi commands
    pub fn ipmi_ctx_set_target(
        ctx: IpmiContextType,
        channel_number: *mut c_uchar,
        rs_addr: *mut c_uchar,
    ) -> c_int;
    /// Inner libfreeipmi C unsafe API - send ipmi commands
    pub fn ipmi_ctx_get_target(
        ctx: IpmiContextType,
        channel_number: *mut c_uchar,
        rs_addr: *mut c_uchar,
    ) -> c_int;
    // ipmi chassis commands api from api/ipmi-chassis-cmds-api.h:
    /// Inner libfreeipmi C unsafe API - get chassis capabilities
    pub fn ipmi_cmd_get_chassis_capabilities(ctx: IpmiContextType, obj_cmd_rs: FiidObj) -> c_int;
    /// Inner libfreeipmi C unsafe API - get chassis status
    pub fn ipmi_cmd_get_chassis_status(ctx: IpmiContextType, obj_cmd_rs: FiidObj) -> c_int;
    /// Inner libfreeipmi C unsafe API - set chassis power state
    pub fn ipmi_cmd_chassis_control(
        ctx: IpmiContextType,
        chassis_control: c_uchar,
        obj_cmd_rs: FiidObj,
    ) -> c_int;
    /// Inner libfreeipmi C unsafe API - chassis identify front panel led control
    pub fn ipmi_cmd_chassis_identify(
        ctx: IpmiContextType,
        identify_interval: *const c_uchar,
        force_identify: *const c_uchar,
        obj_cmd_rs: FiidObj,
    ) -> c_int;
    /// Inner libfreeipmi C unsafe API - set chassis power restore policy
    pub fn ipmi_cmd_set_power_restore_policy(
        ctx: IpmiContextType,
        power_restore_policy: c_uchar,
        obj_cmd_rs: FiidObj,
    ) -> c_int;
    /// Inner libfreeipmi C unsafe API - set chassis power cycle interval
    pub fn ipmi_cmd_set_power_cycle_interval(
        ctx: IpmiContextType,
        interval: c_uchar,
        obj_cmd_rs: FiidObj,
    ) -> c_int;
    /// Inner libfreeipmi C unsafe API - get system restart cause recorded by BMC
    pub fn ipmi_cmd_get_system_restart_cause(ctx: IpmiContextType, obj_cmd_rs: FiidObj) -> c_int;
    /// Inner libfreeipmi C unsafe API - set system boot options
    pub fn ipmi_cmd_set_system_boot_options(
        ctx: IpmiContextType,
        parameter_selector: c_uchar,
        parameter_valid: c_uchar,
        configuration_parameter_data: *const c_void,
        configuration_parameter_data_len: c_uint,
        obj_cmd_rs: FiidObj,
    ) -> c_int;
    /// Inner libfreeipmi C unsafe API - get system boot options
    pub fn ipmi_cmd_get_system_boot_options(
        ctx: IpmiContextType,
        parameter_selector: c_uchar,
        set_selector: c_uchar,
        block_selector: c_uchar,
        obj_cmd_rs: FiidObj,
    ) -> c_int;
    /// Inner libfreeipmi C unsafe API - get system power on hours
    pub fn ipmi_cmd_get_power_on_hours_counter(ctx: IpmiContextType, obj_cmd_rs: FiidObj) -> c_int;
    // helper api functions for chassis cmds in ipmi-chassis-cmds.h
    /// Inner libfreeipmi C unsafe API - fiid api
    pub fn fill_cmd_get_chassis_capabilities(obj_cmd_rq: FiidObj) -> c_int;
    /// Inner libfreeipmi C unsafe API - fiid api
    pub fn fill_cmd_get_chassis_status(obj_cmd_rq: FiidObj) -> c_int;
    /// Inner libfreeipmi C unsafe API - fiid api
    pub fn fill_cmd_chassis_control(chassis_control: c_uchar, obj_cmd_rq: FiidObj) -> c_int;
    /// Inner libfreeipmi C unsafe API - fiid api
    pub fn fill_cmd_chassis_identify(
        identify_interval: *const c_uchar,
        force_identify: *const c_uchar,
        obj_cmd_rq: FiidObj,
    ) -> c_int;
    /// Inner libfreeipmi C unsafe API - fiid api
    pub fn fill_cmd_set_power_restore_policy(
        power_restore_policy: c_uchar,
        obj_cmd_rq: FiidObj,
    ) -> c_int;
    /// Inner libfreeipmi C unsafe API - fiid api
    pub fn fill_cmd_set_power_cycle_interval(interval: c_uchar, obj_cmd_rq: FiidObj) -> c_int;
    /// Inner libfreeipmi C unsafe API - fiid api
    pub fn fill_cmd_get_system_restart_cause(obj_cmd_rq: FiidObj);
    /// Inner libfreeipmi C unsafe API - fiid api
    pub fn fill_cmd_set_system_boot_options(
        parameter_selector: c_uchar,
        parameter_valid: c_uchar,
        configuration_parameter_data: *const c_void,
        configuration_parameter_data_len: c_uint,
        obj_cmd_rq: FiidObj,
    ) -> c_int;
    /// Inner libfreeipmi C unsafe API - fiid api
    pub fn fill_cmd_get_system_boot_options(
        parameter_selector: c_uchar,
        set_selector: c_uchar,
        block_selector: c_uchar,
        obj_cmd_rq: FiidObj,
    ) -> c_int;

    // helper functions from fiid/fiid.h
    /// Inner libfreeipmi C unsafe API - allocate fiid api context object
    pub fn fiid_obj_create(tmpl: *const FiidTemplate) -> FiidObj;
    /// Inner libfreeipmi C unsafe API - cleanup fiid api context object
    pub fn fiid_obj_destroy(obj: FiidObj);
    /// Inner libfreeipmi C unsafe API - query fiid api result object for specific item
    pub fn FIID_OBJ_GET(obj: FiidObj, field: *const c_char, val: *mut c_ulonglong) -> c_int;
}

/// Define a rust native / safe interface to access supported ipmi api calls.
/// This is the *recommended* way to use this crate.
/// It is still possible to directly access the inner low level libfreeipmi api,
/// with management of unsafe blocks and C variables and buffers.
/// Also requires familiarity with ipmi and libfreeipmi.
pub mod ipmi {
    use std::ffi::CString;
    use std::ptr::null_mut;
    use std::{fmt, ptr};

    use libc::{c_int, c_ulonglong};

    use crate::{
        fiid_obj_create, fiid_obj_destroy, ipmi_cmd_chassis_control, ipmi_cmd_get_chassis_status,
        ipmi_ctx_close, ipmi_ctx_create, ipmi_ctx_destroy, ipmi_ctx_open_inband,
        ipmi_ctx_open_outofband, ipmi_ctx_open_outofband_2_0, FiidObj, IpmiAuthenticationType,
        IpmiChassisControl, IpmiChassisIdentifyState, IpmiCipherSuite, IpmiContextType, IpmiDevice,
        IpmiError, IpmiErrorNum, IpmiPrivilegeLevel, PowerRestorePolicyState, FIID_OBJ_GET,
    };
    use crate::{tmpl_cmd_chassis_control_rs, tmpl_cmd_get_chassis_status_rs};

    pub struct ChassisStatusItem {
        query: String,
        value: bool,
    }

    pub struct PowerRestoreStatus {
        query: String,
        value: u8,
    }

    pub struct ChassisIdentifyStatus {
        query: String,
        value: u8,
    }

    impl fmt::Display for ChassisStatusItem {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            write!(f, "{}: {}", self.query, self.value)
        }
    }

    /// Setup an ipmi context for all further calls.
    /// Defaults to IPMI over LAN 2.0 (-I lanplus on ipmitool) and cipher suite 17.
    /// Cleanup the returned context object with destroy().
    pub struct IpmiContext {
        hostname: String,
        interface: IpmiDevice,
        username: String,
        password: String,
        cipher: IpmiCipherSuite,
        /* used for ipmi 2.0 / lanplus */
        level: IpmiPrivilegeLevel,
        auth_mode: IpmiAuthenticationType,
        /* used for ipmi 1.5 / lan */
        freeipmi_ctx: IpmiContextType,
    }

    impl IpmiContext {
        /// Setup a new context in libfreeipmi with the given options for further calls.
        /// Always cleanup the returned context with .destroy().
        /// # Arguments
        ///
        /// * `host` - The hostname or IP address
        /// * `user` - username to login with
        /// * `pass` - password to login with
        /// * `intf` - (optional) IPMI interface type using [crate::ipmi_interface],
        ///    defaults to [crate::ipmi_interface::IPMI_DEVICE_LAN_2_0].
        /// * `algo` - (optional) Cipher suite to use for IPMI 2.0, using [crate::cipher_suite],
        ///    defaults to [crate::cipher_suite::IPMI_CIPHER_HMAC_SHA256_AES_CBC_128].
        /// * `mode` - (optional) Privilege level for the session, using [crate::privilege_level],
        ///    defaults to [crate::privilege_level::IPMI_PRIVILEGE_LEVEL_ADMIN].
        /// * `auth` - (optional) Authentication mode to use for IPMI 1.5, using [crate::auth_type],
        ///    defaults to [crate::auth_type::IPMI_AUTHENTICATION_TYPE_MD5].
        pub fn new(
            host: String,
            user: String,
            pass: String,
            interface: Option<IpmiDevice>,
            algo: Option<IpmiCipherSuite>,
            mode: Option<IpmiPrivilegeLevel>,
            auth: Option<IpmiAuthenticationType>,
        ) -> Self {
            unsafe {
                Self {
                    hostname: host,
                    username: user,
                    password: pass,
                    interface: interface.unwrap_or(IpmiDevice::Lan2_0),
                    cipher: algo.unwrap_or(IpmiCipherSuite::HmacSha256AesCbc128),
                    level: mode.unwrap_or(IpmiPrivilegeLevel::Admin),
                    auth_mode: auth.unwrap_or(IpmiAuthenticationType::Md5),
                    freeipmi_ctx: ipmi_ctx_create(),
                }
            }
        }

        /// Cleanup the rust context, also freeing the libfreeipmi internal context.
        pub fn destroy(&mut self) {
            if !self.freeipmi_ctx.is_null() {
                unsafe {
                    ipmi_ctx_destroy(self.freeipmi_ctx);
                    self.freeipmi_ctx = null_mut();
                }
            }
        }

        /// Setup an IPMI session.
        /// Returns an option result with success or an error string.
        pub fn connect(&mut self) -> Result<(), IpmiError> {
            let c_hostname = CString::new(self.hostname.as_str()).unwrap();
            let c_user = CString::new(self.username.as_str()).unwrap();
            let c_pass = CString::new(self.password.as_str()).unwrap();

            if self.freeipmi_ctx.is_null() {
                return Err(IpmiError::ContextInvalid(
                    IpmiErrorNum::ContextInvalid as i32,
                ));
            }

            let ret = unsafe {
                match self.interface {
                    IpmiDevice::Lan => ipmi_ctx_open_outofband(
                        self.freeipmi_ctx,
                        c_hostname.as_ptr(),
                        c_user.as_ptr(),
                        c_pass.as_ptr(),
                        self.auth_mode as u8,
                        self.level as u8,
                        0,
                        0,
                        0,
                        0,
                    ),
                    IpmiDevice::Lan2_0 => ipmi_ctx_open_outofband_2_0(
                        self.freeipmi_ctx,
                        c_hostname.as_ptr(),
                        c_user.as_ptr(),
                        c_pass.as_ptr(),
                        ptr::null(),
                        0,
                        self.level as u8,
                        self.cipher as u8,
                        0,
                        0,
                        0,
                        0,
                    ),
                    driver_type @ IpmiDevice::Kcs => ipmi_ctx_open_inband(
                        self.freeipmi_ctx,
                        driver_type,
                        0,
                        0,
                        0,
                        null_mut(),
                        0,
                        0,
                    ),
                    _ => -(IpmiErrorNum::DeviceNotSupported as i32),
                }
            };

            if ret < 0 {
                return Err(IpmiError::ConnectionFail(ret as i32));
            }

            Ok(())
        }

        /// Disconnect the IPMI session.
        /// Returns an option result with success or an error string.
        pub fn disconnect(&mut self) -> Result<(), IpmiError> {
            if self.freeipmi_ctx.is_null() {
                return Err(IpmiError::ContextInvalid(
                    IpmiErrorNum::ContextInvalid as i32,
                ));
            }

            unsafe {
                ipmi_ctx_close(self.freeipmi_ctx);
            }
            Ok(())
        }

        /// Set system power state.
        /// Returns an option result with success or an error string.
        /// # Arguments
        /// * `action` - from [crate::power_control]
        pub fn power_control(&mut self, action: IpmiChassisControl) -> Result<(), IpmiError> {
            if self.freeipmi_ctx.is_null() {
                return Err(IpmiError::ContextInvalid(
                    IpmiErrorNum::ContextInvalid as i32,
                ));
            }

            unsafe {
                let obj_cmd_rs: FiidObj = fiid_obj_create(&tmpl_cmd_chassis_control_rs);
                if obj_cmd_rs.is_null() {
                    return Err(IpmiError::FiidObjectAllocate(
                        IpmiErrorNum::OutOfMemory as i32,
                    ));
                }
                let ret: c_int =
                    ipmi_cmd_chassis_control(self.freeipmi_ctx, action as u8, obj_cmd_rs);
                fiid_obj_destroy(obj_cmd_rs);
                if ret < 0 {
                    return Err(IpmiError::PowerControlFail(ret as i32));
                }
            }
            Ok(())
        }

        /// Get chassis status
        /// Returns a vector of [`struct ChassisStatusItem`] or error string
        pub fn chassis_status(&mut self) -> Result<Vec<ChassisStatusItem>, IpmiError> {
            let mut queries: Vec<ChassisStatusItem> = vec![
                ChassisStatusItem {
                    query: String::from("current_power_state.power_is_on"),
                    value: false,
                },
                ChassisStatusItem {
                    query: String::from("current_power_state.power_overload"),
                    value: false,
                },
                ChassisStatusItem {
                    query: String::from("current_power_state.interlock"),
                    value: false,
                },
                ChassisStatusItem {
                    query: String::from("current_power_state.power_fault"),
                    value: false,
                },
                ChassisStatusItem {
                    query: String::from("current_power_state.power_control_fault"),
                    value: false,
                },
                ChassisStatusItem {
                    query: String::from("last_power_event.ac_failed"),
                    value: false,
                },
                ChassisStatusItem {
                    query: String::from("last_power_event.power_down_caused_by_power_overload"),
                    value: false,
                },
                ChassisStatusItem {
                    query: String::from(
                        "last_power_event.power_down_caused_by_power_interlock_being_activated",
                    ),
                    value: false,
                },
                ChassisStatusItem {
                    query: String::from("last_power_event.power_down_caused_by_power_fault"),
                    value: false,
                },
                ChassisStatusItem {
                    query: String::from("last_power_event.power_on_entered_via_ipmi"),
                    value: false,
                },
                ChassisStatusItem {
                    query: String::from("misc_chassis_state.chassis_intrusion_active"),
                    value: false,
                },
                ChassisStatusItem {
                    query: String::from("misc_chassis_state.front_panel_lockout_active"),
                    value: false,
                },
                ChassisStatusItem {
                    query: String::from("misc_chassis_state.drive_fault"),
                    value: false,
                },
                ChassisStatusItem {
                    query: String::from("misc_chassis_state.cooling_fan_fault_detected"),
                    value: false,
                },
                ChassisStatusItem {
                    query: String::from("front_panel.power_off_button_disabled"),
                    value: false,
                },
                ChassisStatusItem {
                    query: String::from("front_panel.reset_button_disabled"),
                    value: false,
                },
                ChassisStatusItem {
                    query: String::from("front_panel.standby_button_disabled"),
                    value: false,
                },
                ChassisStatusItem {
                    query: String::from("front_panel.diagnostic_interrupt_button_disabled"),
                    value: false,
                },
                ChassisStatusItem {
                    query: String::from("front_panel.power_off_button_disable_allowed"),
                    value: false,
                },
                ChassisStatusItem {
                    query: String::from("front_panel.reset_button_disable_allowed"),
                    value: false,
                },
                ChassisStatusItem {
                    query: String::from("front_panel.standby_button_disable_allowed"),
                    value: false,
                },
                ChassisStatusItem {
                    query: String::from("front_panel.diagnostic_interrupt_button_disable_allowed"),
                    value: false,
                },
            ];

            let mut restore_status: PowerRestoreStatus = PowerRestoreStatus {
                query: String::from("current_power_state.power_restore_policy"),
                value: PowerRestorePolicyState::Unknown.into(),
            };

            let mut identify_status: ChassisIdentifyStatus = ChassisIdentifyStatus {
                query: String::from("misc_chassis_state.chassis_identify_state"),
                value: IpmiChassisIdentifyState::Off.into(),
            };

            if self.freeipmi_ctx.is_null() {
                return Err(IpmiError::ContextInvalid(
                    IpmiErrorNum::ContextInvalid as i32,
                ));
            }

            unsafe {
                let obj_cmd_rs: FiidObj = fiid_obj_create(&tmpl_cmd_get_chassis_status_rs);
                let mut val: c_ulonglong = 0;
                let mut c_query: CString;
                if obj_cmd_rs.is_null() {
                    return Err(IpmiError::FiidObjectAllocate(
                        IpmiErrorNum::OutOfMemory as i32,
                    ));
                }
                let mut ret: c_int = ipmi_cmd_get_chassis_status(self.freeipmi_ctx, obj_cmd_rs);
                if ret < 0 {
                    fiid_obj_destroy(obj_cmd_rs);
                    return Err(IpmiError::ChassisStatus(ret as i32));
                }
                // fill the ChassisStatusItem vec and process the 2 additional items
                for item in queries.iter_mut() {
                    c_query = CString::new(item.query.as_str()).unwrap();
                    ret = FIID_OBJ_GET(obj_cmd_rs, c_query.as_ptr(), &mut val);
                    if ret < 0 {
                        // some fiid objects we expect may not be available, depending on bmc.
                        continue;
                    }
                    if val > 0 {
                        item.value = true;
                    }
                }

                // @todo return restore_status and identify_status also
                //  currently only returning chassis status items

                c_query = CString::new(restore_status.query.as_str()).unwrap();
                ret = FIID_OBJ_GET(obj_cmd_rs, c_query.as_ptr(), &mut val);
                if ret == 0 && (val as u8) < PowerRestorePolicyState::Unknown.into() {
                    restore_status.value = val as u8;
                }

                c_query = CString::new(identify_status.query.as_str()).unwrap();
                ret = FIID_OBJ_GET(obj_cmd_rs, c_query.as_ptr(), &mut val);
                if ret == 0 && (val as u8) < IpmiChassisIdentifyState::IndefinitelyOn.into() {
                    identify_status.value = val as u8;
                }
                fiid_obj_destroy(obj_cmd_rs);
            }
            Ok(queries)
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::ipmi::IpmiContext;

    #[test]
    fn it_works() {
        let mut ctx = IpmiContext::new(
            String::from("dummy_host"),
            String::from("Administrator"),
            String::from("password"),
            None,
            None,
            None,
            None,
        );
        ctx.destroy();
    }
}
