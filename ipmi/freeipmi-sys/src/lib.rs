#![allow(non_camel_case_types)]
// we want to match freeipmi names of structs and enums and defines, so we don't do camel case
#![allow(dead_code)]

// WARNING: libfreeipmi is GPLv3!
// Including libfreeipmi headers directly probably means using its sources and creating a derived
// work.

use libc::*;
use num_enum::IntoPrimitive;
use serde::{Deserialize, Serialize};
use std::os::raw::{c_char, c_int, c_uchar, c_uint, c_void};

#[cfg(feature = "libc")]
// relevant enums from the c headers
#[repr(u8)]
#[derive(Copy, Clone, IntoPrimitive)]
/// IPMI interface types, currently only IPMI_DEVICE_LAN and IPMI_DEVICE_LAN_2_0 are supported.
pub enum ipmi_interface {
    IPMI_DEVICE_UNKNOWN = 0,
    IPMI_DEVICE_LAN = 1,
    IPMI_DEVICE_LAN_2_0 = 2,
    IPMI_DEVICE_KCS = 3,
    IPMI_DEVICE_SMIC = 4,
    IPMI_DEVICE_BT = 5,
    IPMI_DEVICE_SSIF = 6,
    IPMI_DEVICE_OPENIPMI = 7,
    IPMI_DEVICE_SUNBMC = 8,
    IPMI_DEVICE_INTELDCMI = 9,
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
pub enum privilege_level {
    IPMI_PRIVILEGE_LEVEL_RESERVED = 0x00,
    /* IPMI_PRIVILEGE_LEVEL_HIGHEST_LEVEL(u8)  = 0x00, IPMI 2.0 */
    /* IPMI_PRIVILEGE_LEVEL_UNSPECIFIED(u8)    = 0x00, RMCP+ Cipher Suite Priv Config */
    IPMI_PRIVILEGE_LEVEL_CALLBACK = 0x01,
    IPMI_PRIVILEGE_LEVEL_USER = 0x02,
    IPMI_PRIVILEGE_LEVEL_OPERATOR = 0x03,
    IPMI_PRIVILEGE_LEVEL_ADMIN = 0x04,
    IPMI_PRIVILEGE_LEVEL_OEM = 0x05,
    IPMI_PRIVILEGE_LEVEL_NO_ACCESS = 0x0F,
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
/// Errors that libfreeipmi typically returns
pub enum ipmi_errnum {
    IPMI_ERR_SUCCESS = 0,
    IPMI_ERR_CTX_NULL = 1,
    IPMI_ERR_CTX_INVALID = 2,
    IPMI_ERR_PERMISSION = 3,
    IPMI_ERR_USERNAME_INVALID = 4,
    IPMI_ERR_PASSWORD_INVALID = 5,
    IPMI_ERR_K_G_INVALID = 6,
    IPMI_ERR_PRIVILEGE_LEVEL_INSUFFICIENT = 7,
    IPMI_ERR_PRIVILEGE_LEVEL_CANNOT_BE_OBTAINED = 8,
    IPMI_ERR_AUTHENTICATION_TYPE_UNAVAILABLE = 9,
    IPMI_ERR_CIPHER_SUITE_ID_UNAVAILABLE = 10,
    IPMI_ERR_PASSWORD_VERIFICATION_TIMEOUT = 11,
    IPMI_ERR_IPMI_2_0_UNAVAILABLE = 12,
    IPMI_ERR_CONNECTION_TIMEOUT = 13,
    IPMI_ERR_SESSION_TIMEOUT = 14,
    IPMI_ERR_DEVICE_ALREADY_OPEN = 15,
    IPMI_ERR_DEVICE_NOT_OPEN = 16,
    IPMI_ERR_DEVICE_NOT_SUPPORTED = 17,
    IPMI_ERR_DEVICE_NOT_FOUND = 18,
    IPMI_ERR_DRIVER_BUSY = 19,
    IPMI_ERR_DRIVER_TIMEOUT = 20,
    IPMI_ERR_MESSAGE_TIMEOUT = 21,
    IPMI_ERR_COMMAND_INVALID_FOR_SELECTED_INTERFACE = 22,
    IPMI_ERR_COMMAND_INVALID_OR_UNSUPPORTED = 23,
    IPMI_ERR_BAD_COMPLETION_CODE = 24,
    IPMI_ERR_BAD_RMCPPLUS_STATUS_CODE = 25,
    IPMI_ERR_NOT_FOUND = 26,
    IPMI_ERR_BMC_BUSY = 27,
    IPMI_ERR_OUT_OF_MEMORY = 28,
    IPMI_ERR_HOSTNAME_INVALID = 29,
    IPMI_ERR_PARAMETERS = 30,
    IPMI_ERR_DRIVER_PATH_REQUIRED = 31,
    IPMI_ERR_IPMI_ERROR = 32,
    IPMI_ERR_SYSTEM_ERROR = 33,
    IPMI_ERR_INTERNAL_ERROR = 34,
    IPMI_ERR_ERRNUMRANGE = 35,
}

#[derive(thiserror::Error, Debug)]
pub enum ipmi_error {
    #[error("freeipmi context not allocated {0}")]
    ipmi_error_ctx_invalid(i32),

    #[error("Failed to open IPMI session {0}")]
    ipmi_error_conn_fail(i32),

    #[error("Failed to set chassis power control {0}")]
    ipmi_error_pwr_ctrl_fail(i32),

    #[error("Failed to allocate internal api object for chassis status {0}")]
    ipmi_error_fiid_obj_alloc(i32),

    #[error("Failed to query chassis status {0}")]
    ipmi_error_chassis_status(i32),

    #[error("Failed to query internal api object for chassis status item {0}")]
    ipmi_error_fiid_query(String, i32),
}

#[repr(u8)]
#[derive(Copy, Clone, IntoPrimitive)]
/// Power restore policy that is returned by querying chassis status
pub enum power_restore_policy_state {
    IPMI_POWER_RESTORE_POLICY_POWERED_OFF_AFTER_AC_RETURNS = 0x00,
    IPMI_POWER_RESTORE_POLICY_POWER_RESTORED_TO_STATE = 0x01,
    IPMI_POWER_RESTORE_POLICY_POWERS_UP_AFTER_AC_RETURNS = 0x02,
    IPMI_POWER_RESTORE_POLICY_UNKNOWN = 0x03,
}

#[repr(u8)]
#[derive(Copy, Clone, IntoPrimitive)]
pub enum power_restore_policy_set {
    IPMI_POWER_RESTORE_POLICY_ALWAYS_STAY_POWERED_OFF = 0x00,
    IPMI_POWER_RESTORE_POLICY_RESTORE_POWER_TO_STATE_WHEN_AC_WAS_LOST = 0x01,
    IPMI_POWER_RESTORE_POLICY_ALWAYS_POWER_UP_AFTER_AC_IS_LOST = 0x02,
    IPMI_POWER_RESTORE_POLICY_NO_CHANGE = 0x03,
}

#[repr(u8)]
#[derive(Copy, Clone, IntoPrimitive)]
pub enum power_state {
    IPMI_SYSTEM_POWER_IS_OFF = 0,
    IPMI_SYSTEM_POWER_IS_ON = 1,
}

#[repr(u8)]
#[derive(Copy, Clone, IntoPrimitive)]
pub enum power_last_event {
    IPMI_LAST_POWER_EVENT_AC_FAILED = 0x00,
    IPMI_LAST_POWER_EVENT_POWER_DOWN_POWER_OVERLOAD = 0x01,
    IPMI_LAST_POWER_EVENT_POWER_DOWN_INTERLOCK_ACTIVATED = 0x02,
    IPMI_LAST_POWER_EVENT_POWER_DOWN_POWER_FAULT = 0x03,
    IPMI_LAST_POWER_EVENT_POWER_ON_VIA_IPMI = 0x04,
    IPMI_LAST_POWER_EVENT_UNKNOWN = 0x05,
}

#[repr(u8)]
#[derive(Copy, Clone, Serialize, Deserialize, IntoPrimitive, Debug)]
pub enum power_control {
    IPMI_CHASSIS_CONTROL_POWER_DOWN = 0x00,
    IPMI_CHASSIS_CONTROL_POWER_UP = 0x01,
    IPMI_CHASSIS_CONTROL_POWER_CYCLE = 0x02,
    IPMI_CHASSIS_CONTROL_HARD_RESET = 0x03,
    IPMI_CHASSIS_CONTROL_PULSE_DIAGNOSTIC_INTERRUPT = 0x04,
    IPMI_CHASSIS_CONTROL_INITIATE_SOFT_SHUTDOWN = 0x05,
}

#[repr(u8)]
#[derive(Copy, Clone, IntoPrimitive)]
pub enum chassis_identify_force {
    IPMI_CHASSIS_FORCE_IDENTIFY_OFF = 0x00,
    IPMI_CHASSIS_FORCE_IDENTIFY_ON = 0x01,
}

#[repr(u8)]
#[derive(Copy, Clone, IntoPrimitive)]
pub enum chassis_identify_state {
    IPMI_CHASSIS_IDENTIFY_STATE_OFF = 0x00,
    IPMI_CHASSIS_IDENTIFY_STATE_TEMPORARY_ON = 0x01,
    IPMI_CHASSIS_IDENTIFY_STATE_INDEFINITE_ON = 0x02,
}

#[repr(u8)]
#[derive(Copy, Clone, IntoPrimitive)]
pub enum chassis_restart_cause {
    IPMI_CHASSIS_SYSTEM_RESTART_CAUSE_UNKNOWN = 0x00,
    IPMI_CHASSIS_SYSTEM_RESTART_CAUSE_CHASSIS_CONTROL_COMMAND = 0x01,
    IPMI_CHASSIS_SYSTEM_RESTART_CAUSE_RESET_VIA_PUSHBUTTON = 0x02,
    IPMI_CHASSIS_SYSTEM_RESTART_CAUSE_POWER_UP_VIA_POWER_PUSHBUTTON = 0x03,
    IPMI_CHASSIS_SYSTEM_RESTART_CAUSE_WATCHDOG_EXPIRATION = 0x04,
    IPMI_CHASSIS_SYSTEM_RESTART_CAUSE_OEM = 0x05,
    IPMI_CHASSIS_SYSTEM_RESTART_CAUSE_AUTOMATIC_POWER_UP_ALWAYS_RESTORE = 0x06,
    IPMI_CHASSIS_SYSTEM_RESTART_CAUSE_AUTOMATIC_POWER_UP_RESTORE_PREVIOUS = 0x07,
    IPMI_CHASSIS_SYSTEM_RESTART_CAUSE_RESET_VIA_PEF = 0x08,
    IPMI_CHASSIS_SYSTEM_RESTART_CAUSE_POWER_CYCLE_VIA_PEF = 0x09,
    IPMI_CHASSIS_SYSTEM_RESTART_CAUSE_SOFT_RESET = 0x0A,
    IPMI_CHASSIS_SYSTEM_RESTART_CAUSE_POWER_UP_VIA_RTC = 0x0B,
}

/// freeipmi api context to pass the opaque library ptr around.
pub type ipmi_ctx_t = *mut c_void;
/// freeipmi fiid api context to pass the opaque library ptr around.
pub type fiid_obj_t = *mut c_void; /* define as struct fiid_obj later */
/// freeipmi fiid api context to pass the opaque library ptr around.
pub type fiid_template_t = c_void;
/// freeipmi fiid api context to pass the opaque library ptr around.
pub type hash_t = *mut c_void;

/// typedefs from the c headers
pub type ipmi_driver_type_t = ipmi_interface;
pub type ipmi_errnum_type_t = ipmi_errnum;

#[link(name = "freeipmi")]
extern "C" {
    /// static fiid api globals from libfreeipmi for chassis cmds in ipmi-chassis-cmds.h

    #[link_name = "tmpl_cmd_get_chassis_capabilities_rq"]
    pub static tmpl_cmd_get_chassis_capabilities_rq: fiid_template_t;

    #[link_name = "tmpl_cmd_get_chassis_capabilities_rs"]
    pub static tmpl_cmd_get_chassis_capabilities_rs: fiid_template_t;

    #[link_name = "tmpl_cmd_get_chassis_status_rq"]
    pub static tmpl_cmd_get_chassis_status_rq: fiid_template_t;

    #[link_name = "tmpl_cmd_get_chassis_status_rs"]
    pub static tmpl_cmd_get_chassis_status_rs: fiid_template_t;

    #[link_name = "tmpl_cmd_chassis_control_rq"]
    pub static tmpl_cmd_chassis_control_rq: fiid_template_t;

    #[link_name = "tmpl_cmd_chassis_control_rs"]
    pub static tmpl_cmd_chassis_control_rs: fiid_template_t;

    #[link_name = "tmpl_cmd_chassis_identify_rq"]
    pub static tmpl_cmd_chassis_identify_rq: fiid_template_t;

    #[link_name = "tmpl_cmd_chassis_identify_rs"]
    pub static tmpl_cmd_chassis_identify_rs: fiid_template_t;

    #[link_name = "tmpl_cmd_set_power_restore_policy_rq"]
    pub static tmpl_cmd_set_power_restore_policy_rq: fiid_template_t;

    #[link_name = "tmpl_cmd_set_power_restore_policy_rs"]
    pub static tmpl_cmd_set_power_restore_policy_rs: fiid_template_t;

    #[link_name = "tmpl_cmd_set_power_cycle_interval_rq"]
    pub static tmpl_cmd_set_power_cycle_interval_rq: fiid_template_t;

    #[link_name = "tmpl_cmd_set_power_cycle_interval_rs"]
    pub static tmpl_cmd_set_power_cycle_interval_rs: fiid_template_t;

    #[link_name = "tmpl_cmd_get_system_restart_cause_rq"]
    pub static tmpl_cmd_get_system_restart_cause_rq: fiid_template_t;

    #[link_name = "tmpl_cmd_get_system_restart_cause_rs"]
    pub static tmpl_cmd_get_system_restart_cause_rs: fiid_template_t;

    #[link_name = "tmpl_cmd_set_system_boot_options_rq"]
    pub static tmpl_cmd_set_system_boot_options_rq: fiid_template_t;

    #[link_name = "tmpl_cmd_set_system_boot_options_rs"]
    pub static tmpl_cmd_set_system_boot_options_rs: fiid_template_t;

    #[link_name = "tmpl_cmd_get_system_boot_options_rq"]
    pub static tmpl_cmd_get_system_boot_options_rq: fiid_template_t;

    #[link_name = "tmpl_cmd_get_system_boot_options_rs"]
    pub static tmpl_cmd_get_system_boot_options_rs: fiid_template_t;

    #[link_name = "tmpl_cmd_get_power_on_hours_counter_rq"]
    pub static tmpl_cmd_get_power_on_hours_counter_rq: fiid_template_t;

    #[link_name = "tmpl_cmd_get_power_on_hours_counter_rs"]
    pub static tmpl_cmd_get_power_on_hours_counter_rs: fiid_template_t;

}

// Functions
#[link(name = "freeipmi")] /* link to existing installed libfreeipmi on build host */
extern "C" {

    // api/ipmi-api.h functions:
    // these are the starting point for establishing an ipmi session to run ipmi commands

    /// Inner libfreeipmi C unsafe API - context creation
    pub fn ipmi_ctx_create() -> ipmi_ctx_t;

    /// Inner libfreeipmi C unsafe API - error retrieval
    pub fn ipmi_ctx_errnum(ctx: ipmi_ctx_t) -> c_int;
    /// Inner libfreeipmi C unsafe API - error retrieval
    pub fn ipmi_ctx_strerror(errnum: c_int) -> *mut c_char;
    /// Inner libfreeipmi C unsafe API - error retrieval
    pub fn ipmi_ctx_errormsg(ctx: ipmi_ctx_t) -> *mut c_char;

    /// Inner libfreeipmi C unsafe API - get context flags
    pub fn ipmi_ctx_get_flags(ctx: ipmi_ctx_t, flags: *mut c_uint) -> c_int;
    /// Inner libfreeipmi C unsafe API - set context flags
    pub fn ipmi_ctx_set_flags(ctx: ipmi_ctx_t, flags: c_uint) -> c_int; // use with care

    /// Inner libfreeipmi C unsafe API - setup IPMI 1.5 lan session
    pub fn ipmi_ctx_open_outofband(
        ctx: ipmi_ctx_t,
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
        ctx: ipmi_ctx_t,
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
        ctx: ipmi_ctx_t,
        driver_type: ipmi_driver_type_t,
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
        ctx: ipmi_ctx_t,
        driver_type: ipmi_driver_type_t,
        disable_auto_probe: c_int,
        driver_address: c_ushort,
        register_spacing: c_uchar,
        driver_device: *const c_char,
        workaround_flags: c_uint,
        flags: c_uint,
    ) -> c_int;

    /// Inner libfreeipmi C unsafe API - close session
    pub fn ipmi_ctx_close(ctx: ipmi_ctx_t) -> c_int;
    /// Inner libfreeipmi C unsafe API - cleanup context
    pub fn ipmi_ctx_destroy(ctx: ipmi_ctx_t);

    /// Inner libfreeipmi C unsafe API - send ipmi commands
    pub fn ipmi_ctx_set_target(
        ctx: ipmi_ctx_t,
        channel_number: *mut c_uchar,
        rs_addr: *mut c_uchar,
    ) -> c_int;
    /// Inner libfreeipmi C unsafe API - send ipmi commands
    pub fn ipmi_ctx_get_target(
        ctx: ipmi_ctx_t,
        channel_number: *mut c_uchar,
        rs_addr: *mut c_uchar,
    ) -> c_int;

    // ipmi chassis commands api from api/ipmi-chassis-cmds-api.h:
    /// Inner libfreeipmi C unsafe API - get chassis capabilities
    pub fn ipmi_cmd_get_chassis_capabilities(ctx: ipmi_ctx_t, obj_cmd_rs: fiid_obj_t) -> c_int;
    /// Inner libfreeipmi C unsafe API - get chassis status
    pub fn ipmi_cmd_get_chassis_status(ctx: ipmi_ctx_t, obj_cmd_rs: fiid_obj_t) -> c_int;
    /// Inner libfreeipmi C unsafe API - set chassis power state
    pub fn ipmi_cmd_chassis_control(
        ctx: ipmi_ctx_t,
        chassis_control: c_uchar,
        obj_cmd_rs: fiid_obj_t,
    ) -> c_int;
    /// Inner libfreeipmi C unsafe API - chassis identify front panel led control
    pub fn ipmi_cmd_chassis_identify(
        ctx: ipmi_ctx_t,
        identify_interval: *const c_uchar,
        force_identify: *const c_uchar,
        obj_cmd_rs: fiid_obj_t,
    ) -> c_int;
    /// Inner libfreeipmi C unsafe API - set chassis power restore policy
    pub fn ipmi_cmd_set_power_restore_policy(
        ctx: ipmi_ctx_t,
        power_restore_policy: c_uchar,
        obj_cmd_rs: fiid_obj_t,
    ) -> c_int;
    /// Inner libfreeipmi C unsafe API - set chassis power cycle interval
    pub fn ipmi_cmd_set_power_cycle_interval(
        ctx: ipmi_ctx_t,
        interval: c_uchar,
        obj_cmd_rs: fiid_obj_t,
    ) -> c_int;
    /// Inner libfreeipmi C unsafe API - get system restart cause recorded by BMC
    pub fn ipmi_cmd_get_system_restart_cause(ctx: ipmi_ctx_t, obj_cmd_rs: fiid_obj_t) -> c_int;
    /// Inner libfreeipmi C unsafe API - set system boot options
    pub fn ipmi_cmd_set_system_boot_options(
        ctx: ipmi_ctx_t,
        parameter_selector: c_uchar,
        parameter_valid: c_uchar,
        configuration_parameter_data: *const c_void,
        configuration_parameter_data_len: c_uint,
        obj_cmd_rs: fiid_obj_t,
    ) -> c_int;
    /// Inner libfreeipmi C unsafe API - get system boot options
    pub fn ipmi_cmd_get_system_boot_options(
        ctx: ipmi_ctx_t,
        parameter_selector: c_uchar,
        set_selector: c_uchar,
        block_selector: c_uchar,
        obj_cmd_rs: fiid_obj_t,
    ) -> c_int;
    /// Inner libfreeipmi C unsafe API - get system power on hours
    pub fn ipmi_cmd_get_power_on_hours_counter(ctx: ipmi_ctx_t, obj_cmd_rs: fiid_obj_t) -> c_int;

    // helper api functions for chassis cmds in ipmi-chassis-cmds.h
    /// Inner libfreeipmi C unsafe API - fiid api
    pub fn fill_cmd_get_chassis_capabilities(obj_cmd_rq: fiid_obj_t) -> c_int;
    /// Inner libfreeipmi C unsafe API - fiid api
    pub fn fill_cmd_get_chassis_status(obj_cmd_rq: fiid_obj_t) -> c_int;
    /// Inner libfreeipmi C unsafe API - fiid api
    pub fn fill_cmd_chassis_control(chassis_control: c_uchar, obj_cmd_rq: fiid_obj_t) -> c_int;
    /// Inner libfreeipmi C unsafe API - fiid api
    pub fn fill_cmd_chassis_identify(
        identify_interval: *const c_uchar,
        force_identify: *const c_uchar,
        obj_cmd_rq: fiid_obj_t,
    ) -> c_int;
    /// Inner libfreeipmi C unsafe API - fiid api
    pub fn fill_cmd_set_power_restore_policy(
        power_restore_policy: c_uchar,
        obj_cmd_rq: fiid_obj_t,
    ) -> c_int;
    /// Inner libfreeipmi C unsafe API - fiid api
    pub fn fill_cmd_set_power_cycle_interval(interval: c_uchar, obj_cmd_rq: fiid_obj_t) -> c_int;
    /// Inner libfreeipmi C unsafe API - fiid api
    pub fn fill_cmd_get_system_restart_cause(obj_cmd_rq: fiid_obj_t);
    /// Inner libfreeipmi C unsafe API - fiid api
    pub fn fill_cmd_set_system_boot_options(
        parameter_selector: c_uchar,
        parameter_valid: c_uchar,
        configuration_parameter_data: *const c_void,
        configuration_parameter_data_len: c_uint,
        obj_cmd_rq: fiid_obj_t,
    ) -> c_int;
    /// Inner libfreeipmi C unsafe API - fiid api
    pub fn fill_cmd_get_system_boot_options(
        parameter_selector: c_uchar,
        set_selector: c_uchar,
        block_selector: c_uchar,
        obj_cmd_rq: fiid_obj_t,
    ) -> c_int;

    // helper functions from fiid/fiid.h
    /// Inner libfreeipmi C unsafe API - allocate fiid api context object
    pub fn fiid_obj_create(tmpl: *const fiid_template_t) -> fiid_obj_t;
    /// Inner libfreeipmi C unsafe API - cleanup fiid api context object
    pub fn fiid_obj_destroy(obj: fiid_obj_t);
    /// Inner libfreeipmi C unsafe API - query fiid api result object for specific item
    pub fn FIID_OBJ_GET(obj: fiid_obj_t, field: *const c_char, val: *mut c_ulonglong) -> c_int;
}

/// Define a rust native / safe interface to access supported ipmi api calls.
/// This is the *recommended* way to use this crate.
/// It is still possible to directly access the inner low level libfreeipmi api,
/// with management of unsafe blocks and C variables and buffers.
/// Also requires familiarity with ipmi and libfreeipmi.
pub mod ipmi {
    use crate::auth_type::IPMI_AUTHENTICATION_TYPE_MD5;
    use crate::chassis_identify_state::IPMI_CHASSIS_IDENTIFY_STATE_INDEFINITE_ON;
    use crate::cipher_suite::IPMI_CIPHER_HMAC_SHA256_AES_CBC_128;
    use crate::ipmi_errnum::{
        IPMI_ERR_CTX_INVALID, IPMI_ERR_DEVICE_NOT_SUPPORTED, IPMI_ERR_OUT_OF_MEMORY,
    };
    use crate::ipmi_interface::{IPMI_DEVICE_KCS, IPMI_DEVICE_LAN, IPMI_DEVICE_LAN_2_0};
    use crate::power_restore_policy_state::IPMI_POWER_RESTORE_POLICY_UNKNOWN;
    use crate::privilege_level::IPMI_PRIVILEGE_LEVEL_ADMIN;
    use crate::{
        auth_type, chassis_identify_state, cipher_suite, fiid_obj_create, fiid_obj_destroy,
        fiid_obj_t, ipmi_cmd_chassis_control, ipmi_cmd_get_chassis_status, ipmi_ctx_close,
        ipmi_ctx_create, ipmi_ctx_destroy, ipmi_ctx_open_inband, ipmi_ctx_open_outofband,
        ipmi_ctx_open_outofband_2_0, ipmi_ctx_t, ipmi_error, ipmi_interface, power_control,
        power_restore_policy_state, privilege_level, FIID_OBJ_GET,
    };
    use crate::{tmpl_cmd_chassis_control_rs, tmpl_cmd_get_chassis_status_rs};
    use libc::{c_int, c_ulonglong};
    use std::ffi::CString;
    use std::ptr::null_mut;
    use std::{fmt, ptr};

    pub struct chassis_status_item {
        query: String,
        value: bool,
    }

    pub struct power_restore_status {
        query: String,
        value: u8,
    }

    pub struct chassis_identify_status {
        query: String,
        value: u8,
    }

    impl std::fmt::Display for chassis_status_item {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            write!(f, "{}: {}", self.query, self.value)
        }
    }

    /// Setup an ipmi context for all further calls.
    /// Defaults to IPMI over LAN 2.0 (-I lanplus on ipmitool) and cipher suite 17.
    /// Cleanup the returned context object with destroy().
    pub struct ipmi_ctx {
        hostname: String,
        interface: ipmi_interface,
        username: String,
        password: String,
        cipher: cipher_suite, /* used for ipmi 2.0 / lanplus */
        level: privilege_level,
        auth_mode: auth_type, /* used for ipmi 1.5 / lan */
        freeipmi_ctx: ipmi_ctx_t,
    }

    impl ipmi_ctx {
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
            intf: Option<ipmi_interface>,
            algo: Option<cipher_suite>,
            mode: Option<privilege_level>,
            auth: Option<auth_type>,
        ) -> ipmi_ctx {
            ipmi_ctx {
                hostname: host,
                username: user,
                password: pass,
                interface: intf.unwrap_or(IPMI_DEVICE_LAN_2_0),
                cipher: algo.unwrap_or(IPMI_CIPHER_HMAC_SHA256_AES_CBC_128),
                level: mode.unwrap_or(IPMI_PRIVILEGE_LEVEL_ADMIN),
                auth_mode: auth.unwrap_or(IPMI_AUTHENTICATION_TYPE_MD5),
                freeipmi_ctx: unsafe { ipmi_ctx_create() },
            }
        }

        /// Cleanup the rust context, also freeing the libfreeipmi internal context.
        pub fn destroy(&mut self) {
            if !self.freeipmi_ctx.is_null() {
                unsafe {
                    ipmi_ctx_destroy(self.freeipmi_ctx);
                    self.freeipmi_ctx = ptr::null_mut();
                }
            }
        }

        /// Setup an IPMI session.
        /// Returns an option result with success or an error string.
        pub fn connect(&mut self) -> Result<(), ipmi_error> {
            let c_hostname = CString::new(self.hostname.as_str()).unwrap();
            let c_user = CString::new(self.username.as_str()).unwrap();
            let c_pass = CString::new(self.password.as_str()).unwrap();

            let ret: c_int;
            let intf: ipmi_interface = self.interface;

            if self.freeipmi_ctx.is_null() {
                return Err(ipmi_error::ipmi_error_ctx_invalid(
                    IPMI_ERR_CTX_INVALID as i32,
                ));
            }

            match intf {
                IPMI_DEVICE_LAN => unsafe {
                    ret = ipmi_ctx_open_outofband(
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
                    );
                },
                IPMI_DEVICE_LAN_2_0 => unsafe {
                    ret = ipmi_ctx_open_outofband_2_0(
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
                    );
                },
                IPMI_DEVICE_KCS => unsafe {
                    ret = ipmi_ctx_open_inband(
                        self.freeipmi_ctx,
                        IPMI_DEVICE_KCS,
                        0,
                        0,
                        0,
                        null_mut(),
                        0,
                        0,
                    );
                },
                _ => ret = -(IPMI_ERR_DEVICE_NOT_SUPPORTED as i32),
            }

            if ret < 0 {
                return Err(ipmi_error::ipmi_error_conn_fail(ret as i32));
            }

            Ok(())
        }

        /// Disconnect the IPMI session.
        /// Returns an option result with success or an error string.
        pub fn disconnect(&mut self) -> Result<(), ipmi_error> {
            if self.freeipmi_ctx.is_null() {
                return Err(ipmi_error::ipmi_error_ctx_invalid(
                    IPMI_ERR_CTX_INVALID as i32,
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
        pub fn power_control(&mut self, action: power_control) -> Result<(), ipmi_error> {
            if self.freeipmi_ctx.is_null() {
                return Err(ipmi_error::ipmi_error_ctx_invalid(
                    IPMI_ERR_CTX_INVALID as i32,
                ));
            }

            unsafe {
                let obj_cmd_rs: fiid_obj_t = fiid_obj_create(&tmpl_cmd_chassis_control_rs);
                if obj_cmd_rs.is_null() {
                    return Err(ipmi_error::ipmi_error_fiid_obj_alloc(
                        IPMI_ERR_OUT_OF_MEMORY as i32,
                    ));
                }
                let ret: c_int =
                    ipmi_cmd_chassis_control(self.freeipmi_ctx, action as u8, obj_cmd_rs);
                fiid_obj_destroy(obj_cmd_rs);
                if ret < 0 {
                    return Err(ipmi_error::ipmi_error_pwr_ctrl_fail(ret as i32));
                }
            }
            Ok(())
        }

        /// Get chassis status
        /// Returns a vector of [`struct chassis_status_item`] or error string
        pub fn chassis_status(&mut self) -> Result<Vec<chassis_status_item>, ipmi_error> {
            let mut queries: Vec<chassis_status_item> = vec![
                chassis_status_item {
                    query: String::from("current_power_state.power_is_on"),
                    value: false,
                },
                chassis_status_item {
                    query: String::from("current_power_state.power_overload"),
                    value: false,
                },
                chassis_status_item {
                    query: String::from("current_power_state.interlock"),
                    value: false,
                },
                chassis_status_item {
                    query: String::from("current_power_state.power_fault"),
                    value: false,
                },
                chassis_status_item {
                    query: String::from("current_power_state.power_control_fault"),
                    value: false,
                },
                chassis_status_item {
                    query: String::from("last_power_event.ac_failed"),
                    value: false,
                },
                chassis_status_item {
                    query: String::from("last_power_event.power_down_caused_by_power_overload"),
                    value: false,
                },
                chassis_status_item {
                    query: String::from(
                        "last_power_event.power_down_caused_by_power_interlock_being_activated",
                    ),
                    value: false,
                },
                chassis_status_item {
                    query: String::from("last_power_event.power_down_caused_by_power_fault"),
                    value: false,
                },
                chassis_status_item {
                    query: String::from("last_power_event.power_on_entered_via_ipmi"),
                    value: false,
                },
                chassis_status_item {
                    query: String::from("misc_chassis_state.chassis_intrusion_active"),
                    value: false,
                },
                chassis_status_item {
                    query: String::from("misc_chassis_state.front_panel_lockout_active"),
                    value: false,
                },
                chassis_status_item {
                    query: String::from("misc_chassis_state.drive_fault"),
                    value: false,
                },
                chassis_status_item {
                    query: String::from("misc_chassis_state.cooling_fan_fault_detected"),
                    value: false,
                },
                chassis_status_item {
                    query: String::from("front_panel.power_off_button_disabled"),
                    value: false,
                },
                chassis_status_item {
                    query: String::from("front_panel.reset_button_disabled"),
                    value: false,
                },
                chassis_status_item {
                    query: String::from("front_panel.standby_button_disabled"),
                    value: false,
                },
                chassis_status_item {
                    query: String::from("front_panel.diagnostic_interrupt_button_disabled"),
                    value: false,
                },
                chassis_status_item {
                    query: String::from("front_panel.power_off_button_disable_allowed"),
                    value: false,
                },
                chassis_status_item {
                    query: String::from("front_panel.reset_button_disable_allowed"),
                    value: false,
                },
                chassis_status_item {
                    query: String::from("front_panel.standby_button_disable_allowed"),
                    value: false,
                },
                chassis_status_item {
                    query: String::from("front_panel.diagnostic_interrupt_button_disable_allowed"),
                    value: false,
                },
            ];

            let mut restore_status: power_restore_status = power_restore_status {
                query: String::from("current_power_state.power_restore_policy"),
                value: power_restore_policy_state::IPMI_POWER_RESTORE_POLICY_UNKNOWN.into(),
            };

            let mut identify_status: chassis_identify_status = chassis_identify_status {
                query: String::from("misc_chassis_state.chassis_identify_state"),
                value: chassis_identify_state::IPMI_CHASSIS_IDENTIFY_STATE_OFF.into(),
            };

            if self.freeipmi_ctx.is_null() {
                return Err(ipmi_error::ipmi_error_ctx_invalid(
                    IPMI_ERR_CTX_INVALID as i32,
                ));
            }

            unsafe {
                let obj_cmd_rs: fiid_obj_t = fiid_obj_create(&tmpl_cmd_get_chassis_status_rs);
                let mut val: c_ulonglong = 0;
                let mut c_query: CString;
                let mut ret: c_int;
                if obj_cmd_rs.is_null() {
                    return Err(ipmi_error::ipmi_error_fiid_obj_alloc(
                        IPMI_ERR_OUT_OF_MEMORY as i32,
                    ));
                }
                ret = ipmi_cmd_get_chassis_status(self.freeipmi_ctx, obj_cmd_rs);
                if ret < 0 {
                    fiid_obj_destroy(obj_cmd_rs);
                    return Err(ipmi_error::ipmi_error_chassis_status(ret as i32));
                }
                // fill the chassis_status_item vec and process the 2 additional items
                for item in queries.iter_mut() {
                    c_query = CString::new(item.query.as_str()).unwrap();
                    ret = FIID_OBJ_GET(obj_cmd_rs, c_query.as_ptr(), &mut val);
                    if ret < 0 {
                        fiid_obj_destroy(obj_cmd_rs);
                        return Err(ipmi_error::ipmi_error_fiid_query(
                            String::from(item.query.as_str()),
                            ret as i32,
                        ));
                    }
                    if val > 0 {
                        item.value = true;
                    }
                }

                // @todo return restore_status and identify_status also
                //  currently only returning chassis status items

                c_query = CString::new(restore_status.query.as_str()).unwrap();
                ret = FIID_OBJ_GET(obj_cmd_rs, c_query.as_ptr(), &mut val);
                if ret < 0 {
                    fiid_obj_destroy(obj_cmd_rs);
                    return Err(ipmi_error::ipmi_error_fiid_query(
                        String::from(restore_status.query.as_str()),
                        ret as i32,
                    ));
                }
                if (val as u8) < IPMI_POWER_RESTORE_POLICY_UNKNOWN.into() {
                    restore_status.value = val as u8;
                }

                c_query = CString::new(identify_status.query.as_str()).unwrap();
                ret = FIID_OBJ_GET(obj_cmd_rs, c_query.as_ptr(), &mut val);
                if ret < 0 {
                    fiid_obj_destroy(obj_cmd_rs);
                    return Err(ipmi_error::ipmi_error_fiid_query(
                        String::from(identify_status.query.as_str()),
                        ret as i32,
                    ));
                }
                if (val as u8) < IPMI_CHASSIS_IDENTIFY_STATE_INDEFINITE_ON.into() {
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
    use crate::ipmi::ipmi_ctx;

    #[test]
    fn it_works() {
        let mut ctx = ipmi_ctx::new(
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
