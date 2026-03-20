/*
 * SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

//! Core IPMI types: network function codes, completion codes, requests, responses.

// Placeholder — will be filled by Phase 1 types sub-agent.

mod fru_types;
mod request;
mod response;
mod sel_types;
mod sensor_types;

pub use fru_types::*;
pub use request::*;
pub use response::*;
pub use sel_types::*;
pub use sensor_types::*;

// ==============================================================================
// Network Function Codes (NetFn)
// ==============================================================================

/// IPMI network function codes. Each request NetFn has a corresponding response
/// NetFn at `request | 0x01`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(into = "u8", try_from = "u8")]
#[repr(u8)]
pub enum NetFn {
    Chassis = 0x00,
    ChassisResponse = 0x01,
    Bridge = 0x02,
    BridgeResponse = 0x03,
    SensorEvent = 0x04,
    SensorEventResponse = 0x05,
    App = 0x06,
    AppResponse = 0x07,
    Firmware = 0x08,
    FirmwareResponse = 0x09,
    Storage = 0x0A,
    StorageResponse = 0x0B,
    Transport = 0x0C,
    TransportResponse = 0x0D,
    // 0x2C-0x2D are group extension, 0x2E-0x2F are OEM/group
    GroupExtension = 0x2C,
    GroupExtensionResponse = 0x2D,
    Oem = 0x2E,
    OemResponse = 0x2F,
}

impl NetFn {
    /// Returns the response NetFn corresponding to this request NetFn.
    #[must_use]
    pub fn response(self) -> u8 {
        (self as u8) | 0x01
    }
}

impl From<NetFn> for u8 {
    fn from(nf: NetFn) -> u8 {
        nf as u8
    }
}

impl TryFrom<u8> for NetFn {
    type Error = u8;

    fn try_from(value: u8) -> std::result::Result<Self, u8> {
        match value {
            0x00 => Ok(Self::Chassis),
            0x01 => Ok(Self::ChassisResponse),
            0x02 => Ok(Self::Bridge),
            0x03 => Ok(Self::BridgeResponse),
            0x04 => Ok(Self::SensorEvent),
            0x05 => Ok(Self::SensorEventResponse),
            0x06 => Ok(Self::App),
            0x07 => Ok(Self::AppResponse),
            0x08 => Ok(Self::Firmware),
            0x09 => Ok(Self::FirmwareResponse),
            0x0A => Ok(Self::Storage),
            0x0B => Ok(Self::StorageResponse),
            0x0C => Ok(Self::Transport),
            0x0D => Ok(Self::TransportResponse),
            0x2C => Ok(Self::GroupExtension),
            0x2D => Ok(Self::GroupExtensionResponse),
            0x2E => Ok(Self::Oem),
            0x2F => Ok(Self::OemResponse),
            other => Err(other),
        }
    }
}

// ==============================================================================
// Completion Codes
// ==============================================================================

/// IPMI completion codes returned by BMCs. See IPMI v2.0 spec Table 5-2.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(into = "u8", from = "u8")]
pub enum CompletionCode {
    /// Command completed normally.
    Success,
    /// Node busy — command could not be processed. Retry.
    NodeBusy,
    /// Invalid command.
    InvalidCommand,
    /// Command invalid for given LUN.
    InvalidCommandForLun,
    /// Timeout while processing command.
    Timeout,
    /// Out of space — insufficient storage.
    OutOfSpace,
    /// Reservation cancelled or invalid reservation ID.
    ReservationCancelled,
    /// Request data truncated.
    RequestDataTruncated,
    /// Request data length invalid.
    RequestDataLengthInvalid,
    /// Request data field length limit exceeded.
    RequestDataFieldLengthExceeded,
    /// Parameter out of range.
    ParameterOutOfRange,
    /// Cannot return number of requested data bytes.
    CannotReturnRequestedDataBytes,
    /// Requested sensor/data/record not present.
    RequestedDataNotPresent,
    /// Invalid data field in request.
    InvalidDataField,
    /// Command illegal for specified sensor or record type.
    IllegalCommand,
    /// Command response could not be provided.
    ResponseNotProvided,
    /// Cannot execute duplicated request.
    DuplicatedRequest,
    /// SDR repository in update mode.
    SdrRepositoryInUpdateMode,
    /// Device in firmware update mode.
    FirmwareUpdateMode,
    /// BMC initialization in progress.
    BmcInitInProgress,
    /// Destination unavailable.
    DestinationUnavailable,
    /// Insufficient privilege level.
    InsufficientPrivilege,
    /// Command not supported in present state.
    CommandNotSupportedInState,
    /// Command sub-function disabled or unavailable.
    SubFunctionDisabled,
    /// Unspecified error.
    Unspecified,
    /// Unknown/OEM completion code.
    Unknown(u8),
}

impl CompletionCode {
    /// Returns `true` if this represents a successful completion.
    #[must_use]
    pub fn is_success(&self) -> bool {
        matches!(self, Self::Success)
    }
}

impl std::fmt::Display for CompletionCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Success => write!(f, "success (0x00)"),
            Self::NodeBusy => write!(f, "node busy (0xC0)"),
            Self::InvalidCommand => write!(f, "invalid command (0xC1)"),
            Self::InvalidCommandForLun => write!(f, "invalid command for LUN (0xC2)"),
            Self::Timeout => write!(f, "timeout (0xC3)"),
            Self::OutOfSpace => write!(f, "out of space (0xC4)"),
            Self::ReservationCancelled => write!(f, "reservation cancelled (0xC5)"),
            Self::RequestDataTruncated => write!(f, "request data truncated (0xC6)"),
            Self::RequestDataLengthInvalid => write!(f, "request data length invalid (0xC7)"),
            Self::RequestDataFieldLengthExceeded => {
                write!(f, "request data field length exceeded (0xC8)")
            }
            Self::ParameterOutOfRange => write!(f, "parameter out of range (0xC9)"),
            Self::CannotReturnRequestedDataBytes => {
                write!(f, "cannot return requested data bytes (0xCA)")
            }
            Self::RequestedDataNotPresent => write!(f, "requested data not present (0xCB)"),
            Self::InvalidDataField => write!(f, "invalid data field (0xCC)"),
            Self::IllegalCommand => write!(f, "illegal command (0xCD)"),
            Self::ResponseNotProvided => write!(f, "response not provided (0xCE)"),
            Self::DuplicatedRequest => write!(f, "duplicated request (0xCF)"),
            Self::SdrRepositoryInUpdateMode => {
                write!(f, "SDR repository in update mode (0xD0)")
            }
            Self::FirmwareUpdateMode => write!(f, "firmware update mode (0xD1)"),
            Self::BmcInitInProgress => write!(f, "BMC initialization in progress (0xD2)"),
            Self::DestinationUnavailable => write!(f, "destination unavailable (0xD3)"),
            Self::InsufficientPrivilege => write!(f, "insufficient privilege (0xD4)"),
            Self::CommandNotSupportedInState => {
                write!(f, "command not supported in state (0xD5)")
            }
            Self::SubFunctionDisabled => write!(f, "sub-function disabled (0xD6)"),
            Self::Unspecified => write!(f, "unspecified error (0xFF)"),
            Self::Unknown(code) => write!(f, "unknown completion code (0x{code:02X})"),
        }
    }
}

impl From<u8> for CompletionCode {
    fn from(byte: u8) -> Self {
        match byte {
            0x00 => Self::Success,
            0xC0 => Self::NodeBusy,
            0xC1 => Self::InvalidCommand,
            0xC2 => Self::InvalidCommandForLun,
            0xC3 => Self::Timeout,
            0xC4 => Self::OutOfSpace,
            0xC5 => Self::ReservationCancelled,
            0xC6 => Self::RequestDataTruncated,
            0xC7 => Self::RequestDataLengthInvalid,
            0xC8 => Self::RequestDataFieldLengthExceeded,
            0xC9 => Self::ParameterOutOfRange,
            0xCA => Self::CannotReturnRequestedDataBytes,
            0xCB => Self::RequestedDataNotPresent,
            0xCC => Self::InvalidDataField,
            0xCD => Self::IllegalCommand,
            0xCE => Self::ResponseNotProvided,
            0xCF => Self::DuplicatedRequest,
            0xD0 => Self::SdrRepositoryInUpdateMode,
            0xD1 => Self::FirmwareUpdateMode,
            0xD2 => Self::BmcInitInProgress,
            0xD3 => Self::DestinationUnavailable,
            0xD4 => Self::InsufficientPrivilege,
            0xD5 => Self::CommandNotSupportedInState,
            0xD6 => Self::SubFunctionDisabled,
            0xFF => Self::Unspecified,
            other => Self::Unknown(other),
        }
    }
}

impl From<CompletionCode> for u8 {
    fn from(code: CompletionCode) -> u8 {
        match code {
            CompletionCode::Success => 0x00,
            CompletionCode::NodeBusy => 0xC0,
            CompletionCode::InvalidCommand => 0xC1,
            CompletionCode::InvalidCommandForLun => 0xC2,
            CompletionCode::Timeout => 0xC3,
            CompletionCode::OutOfSpace => 0xC4,
            CompletionCode::ReservationCancelled => 0xC5,
            CompletionCode::RequestDataTruncated => 0xC6,
            CompletionCode::RequestDataLengthInvalid => 0xC7,
            CompletionCode::RequestDataFieldLengthExceeded => 0xC8,
            CompletionCode::ParameterOutOfRange => 0xC9,
            CompletionCode::CannotReturnRequestedDataBytes => 0xCA,
            CompletionCode::RequestedDataNotPresent => 0xCB,
            CompletionCode::InvalidDataField => 0xCC,
            CompletionCode::IllegalCommand => 0xCD,
            CompletionCode::ResponseNotProvided => 0xCE,
            CompletionCode::DuplicatedRequest => 0xCF,
            CompletionCode::SdrRepositoryInUpdateMode => 0xD0,
            CompletionCode::FirmwareUpdateMode => 0xD1,
            CompletionCode::BmcInitInProgress => 0xD2,
            CompletionCode::DestinationUnavailable => 0xD3,
            CompletionCode::InsufficientPrivilege => 0xD4,
            CompletionCode::CommandNotSupportedInState => 0xD5,
            CompletionCode::SubFunctionDisabled => 0xD6,
            CompletionCode::Unspecified => 0xFF,
            CompletionCode::Unknown(code) => code,
        }
    }
}

// ==============================================================================
// Privilege Levels
// ==============================================================================

/// IPMI session privilege levels.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum PrivilegeLevel {
    Callback = 0x01,
    User = 0x02,
    Operator = 0x03,
    Administrator = 0x04,
    Oem = 0x05,
}

impl From<PrivilegeLevel> for u8 {
    fn from(p: PrivilegeLevel) -> u8 {
        p as u8
    }
}

impl TryFrom<u8> for PrivilegeLevel {
    type Error = u8;

    fn try_from(value: u8) -> std::result::Result<Self, u8> {
        match value {
            0x01 => Ok(Self::Callback),
            0x02 => Ok(Self::User),
            0x03 => Ok(Self::Operator),
            0x04 => Ok(Self::Administrator),
            0x05 => Ok(Self::Oem),
            other => Err(other),
        }
    }
}

impl std::fmt::Display for PrivilegeLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Callback => write!(f, "CALLBACK"),
            Self::User => write!(f, "USER"),
            Self::Operator => write!(f, "OPERATOR"),
            Self::Administrator => write!(f, "ADMINISTRATOR"),
            Self::Oem => write!(f, "OEM"),
        }
    }
}

// ==============================================================================
// Authentication Types
// ==============================================================================

/// RMCP+ authentication algorithm identifiers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum AuthAlgorithm {
    /// RAKP-none — no authentication (insecure, testing only).
    None = 0x00,
    /// RAKP-HMAC-SHA1 (cipher suites 0-3).
    HmacSha1 = 0x01,
    /// RAKP-HMAC-MD5 (cipher suites 6-8).
    HmacMd5 = 0x02,
    /// RAKP-HMAC-SHA256 (cipher suites 15-17).
    HmacSha256 = 0x03,
}

/// RMCP+ integrity algorithm identifiers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum IntegrityAlgorithm {
    None = 0x00,
    HmacSha1_96 = 0x01,
    HmacMd5_128 = 0x02,
    Md5_128 = 0x03,
    HmacSha256_128 = 0x04,
}

/// RMCP+ confidentiality algorithm identifiers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ConfidentialityAlgorithm {
    None = 0x00,
    AesCbc128 = 0x01,
    Xrc4_128 = 0x02,
    Xrc4_40 = 0x03,
}

/// Bundles the three algorithm choices for a cipher suite.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CipherSuiteId {
    pub id: u8,
    pub auth: AuthAlgorithm,
    pub integrity: IntegrityAlgorithm,
    pub confidentiality: ConfidentialityAlgorithm,
}

/// Look up a cipher suite by its numeric ID.
///
/// Returns `None` for unrecognized suite IDs.
/// We support suites 3, 8, 12, and 17 (the most commonly used ones).
/// Intentionally omitting suites 1-2, 4-7, 9-11, 13-16 — they use weaker
/// algorithms or XRC4 which is deprecated and insecure.
#[must_use]
pub fn cipher_suite_by_id(id: u8) -> Option<CipherSuiteId> {
    match id {
        3 => Some(CipherSuiteId {
            id: 3,
            auth: AuthAlgorithm::HmacSha1,
            integrity: IntegrityAlgorithm::HmacSha1_96,
            confidentiality: ConfidentialityAlgorithm::AesCbc128,
        }),
        8 => Some(CipherSuiteId {
            id: 8,
            auth: AuthAlgorithm::HmacMd5,
            integrity: IntegrityAlgorithm::HmacMd5_128,
            confidentiality: ConfidentialityAlgorithm::AesCbc128,
        }),
        12 => Some(CipherSuiteId {
            id: 12,
            auth: AuthAlgorithm::HmacMd5,
            integrity: IntegrityAlgorithm::Md5_128,
            confidentiality: ConfidentialityAlgorithm::AesCbc128,
        }),
        17 => Some(CipherSuiteId {
            id: 17,
            auth: AuthAlgorithm::HmacSha256,
            integrity: IntegrityAlgorithm::HmacSha256_128,
            confidentiality: ConfidentialityAlgorithm::AesCbc128,
        }),
        _ => None,
    }
}

// ==============================================================================
// IPMI Command Identifiers
// ==============================================================================

/// Known IPMI commands, mapping each to its `(NetFn, cmd)` byte pair.
///
/// Replaces raw magic numbers in handler tables and `IpmiRequest` construction.
/// The variants cover every command implemented in the `cmd/` modules plus
/// session-level commands used by the transport layer.
///
/// Use [`IpmiCommand::netfn`] and [`IpmiCommand::cmd`] to get the wire values,
/// or [`IpmiCommand::from_pair`] to look up a variant from received bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IpmiCommand {
    // ── Chassis (NetFn 0x00) ─────────────────────────────────────────
    /// Get Chassis Status (cmd 0x01).
    GetChassisStatus,
    /// Chassis Control — power on/off/cycle/reset/soft (cmd 0x02).
    ChassisControl,
    /// Chassis Identify — blink LEDs (cmd 0x04).
    ChassisIdentify,
    /// Set System Boot Options (cmd 0x08).
    SetBootOptions,
    /// Get System Boot Options (cmd 0x09).
    GetBootOptions,

    // ── App (NetFn 0x06) ─────────────────────────────────────────────
    /// Get Device ID (cmd 0x01).
    GetDeviceId,
    /// Cold Reset (cmd 0x02).
    ColdReset,
    /// Warm Reset (cmd 0x03).
    WarmReset,
    /// Get Self Test Results (cmd 0x04).
    GetSelfTestResults,
    /// Get Device GUID (cmd 0x37).
    GetDeviceGuid,
    /// Reset Watchdog Timer (cmd 0x22).
    ResetWatchdogTimer,
    /// Get Watchdog Timer (cmd 0x25).
    GetWatchdogTimer,
    /// Get Channel Authentication Capabilities (cmd 0x38).
    GetChannelAuthCapabilities,
    /// Set Channel Access (cmd 0x40).
    SetChannelAccess,
    /// Get Channel Access (cmd 0x41).
    GetChannelAccess,
    /// Get Channel Info (cmd 0x42).
    GetChannelInfo,
    /// Set User Access (cmd 0x43).
    SetUserAccess,
    /// Get User Access (cmd 0x44).
    GetUserAccess,
    /// Set User Name (cmd 0x45).
    SetUserName,
    /// Get User Name (cmd 0x46).
    GetUserName,
    /// Set User Password (cmd 0x47).
    SetUserPassword,
    /// Activate Payload — SOL (cmd 0x48).
    ActivatePayload,
    /// Deactivate Payload — SOL (cmd 0x49).
    DeactivatePayload,
    /// Get Channel Cipher Suites (cmd 0x54).
    GetChannelCipherSuites,
    /// Set Session Privilege Level (cmd 0x3B).
    SetSessionPrivilegeLevel,
    /// Close Session (cmd 0x3C).
    CloseSession,

    // ── Sensor/Event (NetFn 0x04) ────────────────────────────────────
    /// Set Sensor Thresholds (cmd 0x26).
    SetSensorThresholds,
    /// Get Sensor Thresholds (cmd 0x27).
    GetSensorThresholds,
    /// Get Sensor Reading (cmd 0x2D).
    GetSensorReading,

    // ── Storage (NetFn 0x0A) ─────────────────────────────────────────
    /// Get FRU Inventory Area Info (cmd 0x10).
    GetFruInventoryAreaInfo,
    /// Read FRU Data (cmd 0x11).
    ReadFruData,
    /// Get SDR Repository Info (cmd 0x20).
    GetSdrRepositoryInfo,
    /// Reserve SDR Repository (cmd 0x22).
    ReserveSdrRepository,
    /// Get SDR (cmd 0x23).
    GetSdr,
    /// Get SEL Info (cmd 0x40).
    GetSelInfo,
    /// Get SEL Entry (cmd 0x43).
    GetSelEntry,
    /// Reserve SEL Repository (cmd 0x42).
    ReserveSelRepository,
    /// Clear SEL (cmd 0x47).
    ClearSel,
    /// Get SEL Time (cmd 0x48).
    GetSelTime,

    // ── Transport (NetFn 0x0C) ───────────────────────────────────────
    /// Set SOL Configuration Parameters (cmd 0x21).
    SetSolConfigParam,
    /// Get SOL Configuration Parameters (cmd 0x22).
    GetSolConfigParam,
}

impl IpmiCommand {
    /// The request network function code for this command.
    #[must_use]
    pub fn netfn(self) -> NetFn {
        match self {
            Self::GetChassisStatus
            | Self::ChassisControl
            | Self::ChassisIdentify
            | Self::SetBootOptions
            | Self::GetBootOptions => NetFn::Chassis,

            Self::GetDeviceId
            | Self::ColdReset
            | Self::WarmReset
            | Self::GetSelfTestResults
            | Self::GetDeviceGuid
            | Self::ResetWatchdogTimer
            | Self::GetWatchdogTimer
            | Self::GetChannelAuthCapabilities
            | Self::SetChannelAccess
            | Self::GetChannelAccess
            | Self::GetChannelInfo
            | Self::SetUserAccess
            | Self::GetUserAccess
            | Self::SetUserName
            | Self::GetUserName
            | Self::SetUserPassword
            | Self::ActivatePayload
            | Self::DeactivatePayload
            | Self::GetChannelCipherSuites
            | Self::SetSessionPrivilegeLevel
            | Self::CloseSession => NetFn::App,

            Self::SetSensorThresholds
            | Self::GetSensorThresholds
            | Self::GetSensorReading => NetFn::SensorEvent,

            Self::GetFruInventoryAreaInfo
            | Self::ReadFruData
            | Self::GetSdrRepositoryInfo
            | Self::ReserveSdrRepository
            | Self::GetSdr
            | Self::GetSelInfo
            | Self::GetSelEntry
            | Self::ReserveSelRepository
            | Self::ClearSel
            | Self::GetSelTime => NetFn::Storage,

            Self::SetSolConfigParam | Self::GetSolConfigParam => NetFn::Transport,
        }
    }

    /// The command code byte for this command.
    #[must_use]
    pub fn cmd(self) -> u8 {
        match self {
            // Chassis
            Self::GetChassisStatus => 0x01,
            Self::ChassisControl => 0x02,
            Self::ChassisIdentify => 0x04,
            Self::SetBootOptions => 0x08,
            Self::GetBootOptions => 0x09,
            // App
            Self::GetDeviceId => 0x01,
            Self::ColdReset => 0x02,
            Self::WarmReset => 0x03,
            Self::GetSelfTestResults => 0x04,
            Self::ResetWatchdogTimer => 0x22,
            Self::GetWatchdogTimer => 0x25,
            Self::GetDeviceGuid => 0x37,
            Self::GetChannelAuthCapabilities => 0x38,
            Self::SetSessionPrivilegeLevel => 0x3B,
            Self::CloseSession => 0x3C,
            Self::SetChannelAccess => 0x40,
            Self::GetChannelAccess => 0x41,
            Self::GetChannelInfo => 0x42,
            Self::SetUserAccess => 0x43,
            Self::GetUserAccess => 0x44,
            Self::SetUserName => 0x45,
            Self::GetUserName => 0x46,
            Self::SetUserPassword => 0x47,
            Self::ActivatePayload => 0x48,
            Self::DeactivatePayload => 0x49,
            Self::GetChannelCipherSuites => 0x54,
            // Sensor/Event
            Self::SetSensorThresholds => 0x26,
            Self::GetSensorThresholds => 0x27,
            Self::GetSensorReading => 0x2D,
            // Storage
            Self::GetFruInventoryAreaInfo => 0x10,
            Self::ReadFruData => 0x11,
            Self::GetSdrRepositoryInfo => 0x20,
            Self::ReserveSdrRepository => 0x22,
            Self::GetSdr => 0x23,
            Self::GetSelInfo => 0x40,
            Self::ReserveSelRepository => 0x42,
            Self::GetSelEntry => 0x43,
            Self::ClearSel => 0x47,
            Self::GetSelTime => 0x48,
            // Transport
            Self::SetSolConfigParam => 0x21,
            Self::GetSolConfigParam => 0x22,
        }
    }

    /// The `(netfn, cmd)` byte pair for use in handler tables.
    #[must_use]
    pub fn pair(self) -> (u8, u8) {
        (self.netfn() as u8, self.cmd())
    }

    /// Look up a command variant from raw `(netfn, cmd)` bytes.
    ///
    /// Returns `None` for unknown combinations. Note that some `(netfn, cmd)`
    /// pairs are ambiguous (e.g., App cmd 0x01 is Get Device ID, Chassis cmd
    /// 0x01 is Get Chassis Status) — the netfn disambiguates.
    #[must_use]
    pub fn from_pair(netfn: u8, cmd: u8) -> Option<Self> {
        // Strip the response bit so callers can pass either request or
        // response netfn values.
        let netfn = netfn & 0xFE;
        match (netfn, cmd) {
            // Chassis
            (0x00, 0x01) => Some(Self::GetChassisStatus),
            (0x00, 0x02) => Some(Self::ChassisControl),
            (0x00, 0x04) => Some(Self::ChassisIdentify),
            (0x00, 0x08) => Some(Self::SetBootOptions),
            (0x00, 0x09) => Some(Self::GetBootOptions),
            // App
            (0x06, 0x01) => Some(Self::GetDeviceId),
            (0x06, 0x02) => Some(Self::ColdReset),
            (0x06, 0x03) => Some(Self::WarmReset),
            (0x06, 0x04) => Some(Self::GetSelfTestResults),
            (0x06, 0x22) => Some(Self::ResetWatchdogTimer),
            (0x06, 0x25) => Some(Self::GetWatchdogTimer),
            (0x06, 0x37) => Some(Self::GetDeviceGuid),
            (0x06, 0x38) => Some(Self::GetChannelAuthCapabilities),
            (0x06, 0x3B) => Some(Self::SetSessionPrivilegeLevel),
            (0x06, 0x3C) => Some(Self::CloseSession),
            (0x06, 0x40) => Some(Self::SetChannelAccess),
            (0x06, 0x41) => Some(Self::GetChannelAccess),
            (0x06, 0x42) => Some(Self::GetChannelInfo),
            (0x06, 0x43) => Some(Self::SetUserAccess),
            (0x06, 0x44) => Some(Self::GetUserAccess),
            (0x06, 0x45) => Some(Self::SetUserName),
            (0x06, 0x46) => Some(Self::GetUserName),
            (0x06, 0x47) => Some(Self::SetUserPassword),
            (0x06, 0x48) => Some(Self::ActivatePayload),
            (0x06, 0x49) => Some(Self::DeactivatePayload),
            (0x06, 0x54) => Some(Self::GetChannelCipherSuites),
            // Sensor/Event
            (0x04, 0x26) => Some(Self::SetSensorThresholds),
            (0x04, 0x27) => Some(Self::GetSensorThresholds),
            (0x04, 0x2D) => Some(Self::GetSensorReading),
            // Storage
            (0x0A, 0x10) => Some(Self::GetFruInventoryAreaInfo),
            (0x0A, 0x11) => Some(Self::ReadFruData),
            (0x0A, 0x20) => Some(Self::GetSdrRepositoryInfo),
            (0x0A, 0x22) => Some(Self::ReserveSdrRepository),
            (0x0A, 0x23) => Some(Self::GetSdr),
            (0x0A, 0x40) => Some(Self::GetSelInfo),
            (0x0A, 0x42) => Some(Self::ReserveSelRepository),
            (0x0A, 0x43) => Some(Self::GetSelEntry),
            (0x0A, 0x47) => Some(Self::ClearSel),
            (0x0A, 0x48) => Some(Self::GetSelTime),
            // Transport
            (0x0C, 0x21) => Some(Self::SetSolConfigParam),
            (0x0C, 0x22) => Some(Self::GetSolConfigParam),
            _ => None,
        }
    }
}

impl std::fmt::Display for IpmiCommand {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn netfn_roundtrip() {
        for nf in [
            NetFn::Chassis,
            NetFn::App,
            NetFn::Storage,
            NetFn::Transport,
        ] {
            let byte: u8 = nf.into();
            let back = NetFn::try_from(byte).expect("valid netfn");
            assert_eq!(nf, back);
        }
    }

    #[test]
    fn netfn_response_bit() {
        assert_eq!(NetFn::Chassis.response(), 0x01);
        assert_eq!(NetFn::App.response(), 0x07);
        assert_eq!(NetFn::Storage.response(), 0x0B);
    }

    #[test]
    fn completion_code_roundtrip() {
        for byte in 0x00..=0xFF {
            let code = CompletionCode::from(byte);
            let back: u8 = code.into();
            assert_eq!(byte, back, "roundtrip failed for 0x{byte:02X}");
        }
    }

    #[test]
    fn completion_code_display() {
        assert_eq!(CompletionCode::Success.to_string(), "success (0x00)");
        assert_eq!(CompletionCode::NodeBusy.to_string(), "node busy (0xC0)");
        assert_eq!(
            CompletionCode::Unknown(0xAB).to_string(),
            "unknown completion code (0xAB)"
        );
    }

    #[test]
    fn cipher_suite_17_is_sha256_aes() {
        let suite = cipher_suite_by_id(17).expect("suite 17 should exist");
        assert_eq!(suite.auth, AuthAlgorithm::HmacSha256);
        assert_eq!(suite.integrity, IntegrityAlgorithm::HmacSha256_128);
        assert_eq!(suite.confidentiality, ConfidentialityAlgorithm::AesCbc128);
    }

    #[test]
    fn unknown_cipher_suite_returns_none() {
        assert!(cipher_suite_by_id(99).is_none());
    }

    #[test]
    fn privilege_level_ordering() {
        assert!(PrivilegeLevel::User < PrivilegeLevel::Operator);
        assert!(PrivilegeLevel::Operator < PrivilegeLevel::Administrator);
    }

    #[test]
    fn ipmi_command_pair_roundtrip() {
        // Every variant must survive a pair() → from_pair() roundtrip.
        let all_commands = [
            IpmiCommand::GetChassisStatus,
            IpmiCommand::ChassisControl,
            IpmiCommand::ChassisIdentify,
            IpmiCommand::SetBootOptions,
            IpmiCommand::GetBootOptions,
            IpmiCommand::GetDeviceId,
            IpmiCommand::ColdReset,
            IpmiCommand::WarmReset,
            IpmiCommand::GetSelfTestResults,
            IpmiCommand::GetDeviceGuid,
            IpmiCommand::ResetWatchdogTimer,
            IpmiCommand::GetWatchdogTimer,
            IpmiCommand::GetChannelAuthCapabilities,
            IpmiCommand::SetChannelAccess,
            IpmiCommand::GetChannelAccess,
            IpmiCommand::GetChannelInfo,
            IpmiCommand::SetUserAccess,
            IpmiCommand::GetUserAccess,
            IpmiCommand::SetUserName,
            IpmiCommand::GetUserName,
            IpmiCommand::SetUserPassword,
            IpmiCommand::ActivatePayload,
            IpmiCommand::DeactivatePayload,
            IpmiCommand::GetChannelCipherSuites,
            IpmiCommand::SetSessionPrivilegeLevel,
            IpmiCommand::CloseSession,
            IpmiCommand::SetSensorThresholds,
            IpmiCommand::GetSensorThresholds,
            IpmiCommand::GetSensorReading,
            IpmiCommand::GetFruInventoryAreaInfo,
            IpmiCommand::ReadFruData,
            IpmiCommand::GetSdrRepositoryInfo,
            IpmiCommand::ReserveSdrRepository,
            IpmiCommand::GetSdr,
            IpmiCommand::GetSelInfo,
            IpmiCommand::GetSelEntry,
            IpmiCommand::ReserveSelRepository,
            IpmiCommand::ClearSel,
            IpmiCommand::GetSelTime,
            IpmiCommand::SetSolConfigParam,
            IpmiCommand::GetSolConfigParam,
        ];

        for cmd in all_commands {
            let (netfn, code) = cmd.pair();
            let back = IpmiCommand::from_pair(netfn, code)
                .unwrap_or_else(|| panic!("from_pair failed for {cmd:?} = (0x{netfn:02x}, 0x{code:02x})"));
            assert_eq!(cmd, back, "roundtrip failed for {cmd:?}");
        }
    }

    #[test]
    fn ipmi_command_from_pair_unknown_returns_none() {
        assert!(IpmiCommand::from_pair(0x06, 0xFF).is_none());
        assert!(IpmiCommand::from_pair(0xFF, 0x01).is_none());
    }

    #[test]
    fn ipmi_command_from_pair_accepts_response_netfn() {
        // Passing the response netfn (odd) should still resolve.
        let cmd = IpmiCommand::from_pair(0x07, 0x01); // App response
        assert_eq!(cmd, Some(IpmiCommand::GetDeviceId));
    }
}
