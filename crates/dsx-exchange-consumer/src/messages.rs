/*
 * SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */

//! Cronus BMS message types defined from the AsyncAPI spec in cronus.yaml.
//!
//! This module contains the message types for leak detection events published
//! by Cronus on the DSX Exchange Event Bus.

use chrono::{DateTime, Utc};
use health_report::HealthProbeId;
use serde::{Deserialize, Deserializer, Serialize, Serializer, de};

/// Point type identifier for leak detection events.
///
/// Note: Variant names match the Cronus AsyncAPI spec exactly.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[allow(clippy::enum_variant_names)]
pub enum LeakPointType {
    /// Rack-level leak detection. Binary value: 0 = No Leak, 1 = Leak Detected.
    LeakDetectRack,
    /// Rack-level leak sensor fault. Binary value: 0 = OK, 1 = Fault.
    LeakSensorFaultRack,
    /// Rack tray leak detection. Binary value: 0 = No Leak, 1 = Leak Detected.
    LeakDetectRackTray,
}

impl LeakPointType {
    /// Returns the health probe ID for this leak type.
    pub fn probe_id(&self) -> HealthProbeId {
        match self {
            LeakPointType::LeakDetectRack => "BmsLeakDetectRack",
            LeakPointType::LeakSensorFaultRack => "BmsLeakSensorFaultRack",
            LeakPointType::LeakDetectRackTray => "BmsLeakDetectRackTray",
        }
        .parse()
        .expect("non-empty strings are always valid probe ids")
    }

    /// Returns a human-readable description for alert messages.
    pub fn description(&self) -> &'static str {
        match self {
            LeakPointType::LeakDetectRack => "Leak detected",
            LeakPointType::LeakSensorFaultRack => "Leak sensor fault",
            LeakPointType::LeakDetectRackTray => "Rack tray leak detected",
        }
    }
}

/// Fault value from BMS points.
///
/// Deserialized from f64 where 0.0 = Clear and 1.0 = Active.
/// - For leak detection: Clear = No Leak, Active = Leak Detected
/// - For sensor fault: Clear = OK, Active = Fault
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FaultValue {
    /// Value is 0 (no leak / OK).
    Clear,
    /// Value is 1 (leak detected / fault).
    Faulting,
}

impl Serialize for FaultValue {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            FaultValue::Clear => serializer.serialize_u8(0),
            FaultValue::Faulting => serializer.serialize_u8(1),
        }
    }
}

impl<'de> Deserialize<'de> for FaultValue {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct BinaryValueVisitor;

        impl<'de> de::Visitor<'de> for BinaryValueVisitor {
            type Value = FaultValue;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("0 or 1")
            }

            fn visit_u64<E: de::Error>(self, v: u64) -> Result<Self::Value, E> {
                match v {
                    0 => Ok(FaultValue::Clear),
                    1 => Ok(FaultValue::Faulting),
                    other => Err(E::custom(format!(
                        "invalid binary value: expected 0 or 1, got {other}"
                    ))),
                }
            }

            fn visit_f64<E: de::Error>(self, v: f64) -> Result<Self::Value, E> {
                // JSON parsers may represent 0.0/1.0 as floats
                if v == 0.0 {
                    Ok(FaultValue::Clear)
                } else if v == 1.0 {
                    Ok(FaultValue::Faulting)
                } else {
                    Err(E::custom(format!(
                        "invalid binary value: expected 0 or 1, got {v}"
                    )))
                }
            }
        }

        deserializer.deserialize_any(BinaryValueVisitor)
    }
}

/// Value message for all BMS points.
///
/// Published on `cronus/v1/{pointPath}/Value` topics.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ValueMessage {
    /// Binary value for the point.
    /// - Leak detection: Clear = No Leak, Active = Leak Detected
    /// - Sensor fault: Clear = OK, Active = Fault
    pub value: FaultValue,
    /// Timestamp corresponding to the event (deserialized from unix timestamp seconds).
    #[serde(with = "chrono::serde::ts_seconds")]
    pub timestamp: DateTime<Utc>,
}

/// Unified metadata type that can represent any of the leak detection metadata types.
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct LeakMetadata {
    /// Canonical point type identifier.
    pub point_type: String,
    /// Canonical object type.
    pub object_type: String,
    /// Human-readable rack name as defined by the BMS.
    pub rack_name: String,
    /// Stable unique identifier for the rack. Maps to racks.id in the database.
    #[serde(rename = "rackID")]
    pub rack_id: String,
}

impl LeakMetadata {
    /// Check if this is a leak detection point type we care about.
    pub fn is_supported_leak_type(&self) -> bool {
        matches!(
            self.point_type.as_str(),
            "LeakDetectRack" | "LeakSensorFaultRack" | "LeakDetectRackTray"
        )
    }

    /// Get the leak point type enum variant.
    pub fn leak_point_type(&self) -> Option<LeakPointType> {
        match self.point_type.as_str() {
            "LeakDetectRack" => Some(LeakPointType::LeakDetectRack),
            "LeakSensorFaultRack" => Some(LeakPointType::LeakSensorFaultRack),
            "LeakDetectRackTray" => Some(LeakPointType::LeakDetectRackTray),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_leak_detect_rack_metadata() {
        let json = r#"{
            "pointType": "LeakDetectRack",
            "objectType": "Rack",
            "rackName": "Rack-01",
            "rackID": "rack-001"
        }"#;

        let metadata: LeakMetadata = serde_json::from_str(json).unwrap();
        assert_eq!(metadata.point_type, "LeakDetectRack");
        assert_eq!(metadata.object_type, "Rack");
        assert_eq!(metadata.rack_name, "Rack-01");
        assert_eq!(metadata.rack_id, "rack-001");
        assert!(metadata.is_supported_leak_type());
        assert_eq!(
            metadata.leak_point_type(),
            Some(LeakPointType::LeakDetectRack)
        );
    }

    #[test]
    fn test_parse_value_message_active_int() {
        let json = r#"{"value": 1, "timestamp": 1706284800}"#;
        let value: ValueMessage = serde_json::from_str(json).unwrap();
        assert_eq!(value.value, FaultValue::Faulting);
    }

    #[test]
    fn test_parse_value_message_active_float() {
        let json = r#"{"value": 1.0, "timestamp": 1706284800}"#;
        let value: ValueMessage = serde_json::from_str(json).unwrap();
        assert_eq!(value.value, FaultValue::Faulting);
        // 1706284800 = 2024-01-26T12:00:00Z
        assert_eq!(value.timestamp.timestamp(), 1706284800);
        assert_eq!(
            value.timestamp,
            DateTime::from_timestamp(1706284800, 0).unwrap()
        );
    }

    #[test]
    fn test_parse_value_message_clear_int() {
        let json = r#"{"value": 0, "timestamp": 1706284800}"#;
        let value: ValueMessage = serde_json::from_str(json).unwrap();
        assert_eq!(value.value, FaultValue::Clear);
    }

    #[test]
    fn test_parse_value_message_clear_float() {
        let json = r#"{"value": 0.0, "timestamp": 1706284800}"#;
        let value: ValueMessage = serde_json::from_str(json).unwrap();
        assert_eq!(value.value, FaultValue::Clear);
    }

    #[test]
    fn test_parse_value_message_invalid_int() {
        let json = r#"{"value": 2, "timestamp": 1706284800}"#;
        let result: Result<ValueMessage, _> = serde_json::from_str(json);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("invalid binary value")
        );
    }

    #[test]
    fn test_parse_value_message_invalid_float() {
        let json = r#"{"value": 0.5, "timestamp": 1706284800}"#;
        let result: Result<ValueMessage, _> = serde_json::from_str(json);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("invalid binary value")
        );
    }

    #[test]
    fn test_unsupported_point_type() {
        let metadata = LeakMetadata {
            point_type: "LeakResponseRackLiquidIsolationStatus".to_string(),
            object_type: "Rack".to_string(),
            rack_name: "Rack-01".to_string(),
            rack_id: "rack-001".to_string(),
        };
        assert!(!metadata.is_supported_leak_type());
        assert_eq!(metadata.leak_point_type(), None);
    }
}
