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

//! Sensor types, reading conversion formula, linearization, and units.

// ==============================================================================
// Sensor Reading Conversion
// ==============================================================================
//
// IPMI threshold sensors report raw values that must be converted using
// the formula from the SDR (IPMI v2.0 spec section 36.3):
//
//   value = L((m * raw + b * 10^k1) * 10^k2)
//
// Where:
//   m, b     = signed multiplier and offset from SDR
//   k1 (b_exp) = signed exponent for b
//   k2 (r_exp) = signed exponent for result
//   L        = linearization function (linear, log, exp, etc.)
//   raw      = unsigned 8-bit sensor reading

/// Linearization functions for sensor readings.
/// See IPMI v2.0 spec Table 43-15.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Linearization {
    Linear = 0x00,
    Ln = 0x01,
    Log10 = 0x02,
    Log2 = 0x03,
    Exp = 0x04,
    Exp10 = 0x05,
    Exp2 = 0x06,
    OneOverX = 0x07,
    Sqr = 0x08,
    Cube = 0x09,
    Sqrt = 0x0A,
    CubeRoot = 0x0B,
    NonLinear = 0x70,
}

impl TryFrom<u8> for Linearization {
    type Error = u8;

    fn try_from(value: u8) -> Result<Self, u8> {
        match value {
            0x00 => Ok(Self::Linear),
            0x01 => Ok(Self::Ln),
            0x02 => Ok(Self::Log10),
            0x03 => Ok(Self::Log2),
            0x04 => Ok(Self::Exp),
            0x05 => Ok(Self::Exp10),
            0x06 => Ok(Self::Exp2),
            0x07 => Ok(Self::OneOverX),
            0x08 => Ok(Self::Sqr),
            0x09 => Ok(Self::Cube),
            0x0A => Ok(Self::Sqrt),
            0x0B => Ok(Self::CubeRoot),
            0x70 => Ok(Self::NonLinear),
            other => Err(other),
        }
    }
}

/// Parameters for converting a raw sensor reading to a human-readable value.
/// Extracted from the SDR Full Sensor Record (type 0x01).
#[derive(Debug, Clone, Copy)]
pub struct SensorConversionFactors {
    /// Signed multiplier (10-bit, sign-extended).
    pub m: i16,
    /// Signed offset (10-bit, sign-extended).
    pub b: i16,
    /// Exponent for b (4-bit signed, range -8..7).
    pub b_exp: i8,
    /// Result exponent (4-bit signed, range -8..7).
    pub r_exp: i8,
    /// Linearization function.
    pub linearization: Linearization,
}

impl SensorConversionFactors {
    /// Convert a raw sensor reading to a floating-point value using the
    /// IPMI sensor conversion formula.
    ///
    /// Formula: `L((m * raw + b * 10^b_exp) * 10^r_exp)`
    #[must_use]
    pub fn convert(&self, raw: u8) -> f64 {
        let m = f64::from(self.m);
        let b = f64::from(self.b);
        let b_exp = f64::from(self.b_exp);
        let r_exp = f64::from(self.r_exp);
        let raw = f64::from(raw);

        let value = (m * raw + b * 10_f64.powf(b_exp)) * 10_f64.powf(r_exp);

        apply_linearization(self.linearization, value)
    }
}

/// Apply the linearization function L to a value.
fn apply_linearization(lin: Linearization, value: f64) -> f64 {
    match lin {
        Linearization::Linear => value,
        Linearization::Ln => value.ln(),
        Linearization::Log10 => value.log10(),
        Linearization::Log2 => value.log2(),
        Linearization::Exp => value.exp(),
        Linearization::Exp10 => 10_f64.powf(value),
        Linearization::Exp2 => 2_f64.powf(value),
        Linearization::OneOverX => 1.0 / value,
        Linearization::Sqr => value * value,
        Linearization::Cube => value * value * value,
        Linearization::Sqrt => value.sqrt(),
        Linearization::CubeRoot => value.cbrt(),
        // Non-linear sensors use OEM-specific conversion; we pass through raw.
        Linearization::NonLinear => value,
    }
}

/// Sensor unit type codes from IPMI v2.0 spec Table 43-15.
/// Only commonly-used units are enumerated; others are captured as `Other(u8)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SensorUnit {
    Unspecified,
    DegreesC,
    DegreesF,
    DegreesK,
    Volts,
    Amps,
    Watts,
    Rpm,
    Hz,
    Percent,
    Seconds,
    Milliseconds,
    Other(u8),
}

impl From<u8> for SensorUnit {
    fn from(byte: u8) -> Self {
        match byte {
            0 => Self::Unspecified,
            1 => Self::DegreesC,
            2 => Self::DegreesF,
            3 => Self::DegreesK,
            4 => Self::Volts,
            5 => Self::Amps,
            6 => Self::Watts,
            18 => Self::Rpm,
            19 => Self::Hz,
            21 => Self::Percent,
            22 => Self::Seconds,
            23 => Self::Milliseconds,
            other => Self::Other(other),
        }
    }
}

impl std::fmt::Display for SensorUnit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unspecified => write!(f, "unspecified"),
            Self::DegreesC => write!(f, "degrees C"),
            Self::DegreesF => write!(f, "degrees F"),
            Self::DegreesK => write!(f, "Kelvin"),
            Self::Volts => write!(f, "Volts"),
            Self::Amps => write!(f, "Amps"),
            Self::Watts => write!(f, "Watts"),
            Self::Rpm => write!(f, "RPM"),
            Self::Hz => write!(f, "Hz"),
            Self::Percent => write!(f, "%"),
            Self::Seconds => write!(f, "seconds"),
            Self::Milliseconds => write!(f, "milliseconds"),
            Self::Other(code) => write!(f, "unit({code})"),
        }
    }
}

/// The type of sensor (temperature, voltage, fan, etc.).
/// See IPMI v2.0 spec Table 42-3.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SensorType {
    Temperature,
    Voltage,
    Current,
    Fan,
    PhysicalSecurity,
    PlatformSecurity,
    Processor,
    PowerSupply,
    PowerUnit,
    Memory,
    SystemFirmwareProgress,
    EventLoggingDisabled,
    SystemEvent,
    CriticalInterrupt,
    ButtonSwitch,
    ChipSet,
    Cable,
    SystemBoot,
    OsBootStatus,
    OsCriticalStop,
    SlotConnector,
    Watchdog2,
    ManagementSubsystemHealth,
    Battery,
    SessionAudit,
    VersionChange,
    FruState,
    Other(u8),
}

impl From<u8> for SensorType {
    fn from(byte: u8) -> Self {
        match byte {
            0x01 => Self::Temperature,
            0x02 => Self::Voltage,
            0x03 => Self::Current,
            0x04 => Self::Fan,
            0x05 => Self::PhysicalSecurity,
            0x06 => Self::PlatformSecurity,
            0x07 => Self::Processor,
            0x08 => Self::PowerSupply,
            0x09 => Self::PowerUnit,
            0x0C => Self::Memory,
            0x0F => Self::SystemFirmwareProgress,
            0x10 => Self::EventLoggingDisabled,
            0x12 => Self::SystemEvent,
            0x13 => Self::CriticalInterrupt,
            0x14 => Self::ButtonSwitch,
            0x19 => Self::ChipSet,
            0x1B => Self::Cable,
            0x1D => Self::SystemBoot,
            0x1E => Self::OsBootStatus,
            0x20 => Self::OsCriticalStop,
            0x21 => Self::SlotConnector,
            0x23 => Self::Watchdog2,
            0x28 => Self::ManagementSubsystemHealth,
            0x29 => Self::Battery,
            0x2A => Self::SessionAudit,
            0x2B => Self::VersionChange,
            0x2C => Self::FruState,
            other => Self::Other(other),
        }
    }
}

impl std::fmt::Display for SensorType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Temperature => write!(f, "Temperature"),
            Self::Voltage => write!(f, "Voltage"),
            Self::Current => write!(f, "Current"),
            Self::Fan => write!(f, "Fan"),
            Self::PhysicalSecurity => write!(f, "Physical Security"),
            Self::PlatformSecurity => write!(f, "Platform Security"),
            Self::Processor => write!(f, "Processor"),
            Self::PowerSupply => write!(f, "Power Supply"),
            Self::PowerUnit => write!(f, "Power Unit"),
            Self::Memory => write!(f, "Memory"),
            Self::SystemFirmwareProgress => write!(f, "System Firmware Progress"),
            Self::EventLoggingDisabled => write!(f, "Event Logging Disabled"),
            Self::SystemEvent => write!(f, "System Event"),
            Self::CriticalInterrupt => write!(f, "Critical Interrupt"),
            Self::ButtonSwitch => write!(f, "Button/Switch"),
            Self::ChipSet => write!(f, "Chip Set"),
            Self::Cable => write!(f, "Cable/Interconnect"),
            Self::SystemBoot => write!(f, "System Boot Initiated"),
            Self::OsBootStatus => write!(f, "OS Boot"),
            Self::OsCriticalStop => write!(f, "OS Critical Stop"),
            Self::SlotConnector => write!(f, "Slot/Connector"),
            Self::Watchdog2 => write!(f, "Watchdog 2"),
            Self::ManagementSubsystemHealth => write!(f, "Management Subsystem Health"),
            Self::Battery => write!(f, "Battery"),
            Self::SessionAudit => write!(f, "Session Audit"),
            Self::VersionChange => write!(f, "Version Change"),
            Self::FruState => write!(f, "FRU State"),
            Self::Other(code) => write!(f, "Sensor Type 0x{code:02X}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn linear_conversion_simple() {
        // m=1, b=0, exponents=0 → value = raw
        let factors = SensorConversionFactors {
            m: 1,
            b: 0,
            b_exp: 0,
            r_exp: 0,
            linearization: Linearization::Linear,
        };
        assert!((factors.convert(100) - 100.0).abs() < f64::EPSILON);
    }

    #[test]
    fn linear_conversion_with_multiplier_and_offset() {
        // A typical temperature sensor: m=1, b=-64, b_exp=0, r_exp=0
        // value = (1 * 200 + (-64) * 1) * 1 = 136
        let factors = SensorConversionFactors {
            m: 1,
            b: -64,
            b_exp: 0,
            r_exp: 0,
            linearization: Linearization::Linear,
        };
        assert!((factors.convert(200) - 136.0).abs() < f64::EPSILON);
    }

    #[test]
    fn conversion_with_exponents() {
        // m=2, b=5, b_exp=1, r_exp=-1
        // value = (2 * 100 + 5 * 10^1) * 10^(-1) = (200 + 50) * 0.1 = 25.0
        let factors = SensorConversionFactors {
            m: 2,
            b: 5,
            b_exp: 1,
            r_exp: -1,
            linearization: Linearization::Linear,
        };
        assert!((factors.convert(100) - 25.0).abs() < 1e-10);
    }

    #[test]
    fn sqrt_linearization() {
        let factors = SensorConversionFactors {
            m: 1,
            b: 0,
            b_exp: 0,
            r_exp: 0,
            linearization: Linearization::Sqrt,
        };
        // sqrt(144) = 12
        assert!((factors.convert(144) - 12.0).abs() < 1e-10);
    }

    #[test]
    fn sensor_unit_display() {
        assert_eq!(SensorUnit::DegreesC.to_string(), "degrees C");
        assert_eq!(SensorUnit::Watts.to_string(), "Watts");
        assert_eq!(SensorUnit::Rpm.to_string(), "RPM");
    }

    #[test]
    fn sensor_type_roundtrip() {
        assert_eq!(SensorType::from(0x01), SensorType::Temperature);
        assert_eq!(SensorType::from(0x04), SensorType::Fan);
        assert_eq!(SensorType::from(0x99), SensorType::Other(0x99));
    }
}
