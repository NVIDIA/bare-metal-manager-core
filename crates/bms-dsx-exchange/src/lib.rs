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

pub mod publisher;
pub mod source_mapping;

pub use publisher::{BmsDsxExchangePublisher, Publication, PublisherConfig};
use serde::ser::SerializeMap;
use serde::{Deserialize, Serialize, Serializer};
pub use source_mapping::{SourceId, SourceUpdate, SourceValue};

pub const GOOD_QUALITY: &str = "1";

const OBJECT_TYPE_RACK: &str = "Rack";
const OBJECT_TYPE_SYSTEM: &str = "System";

const POINT_TYPE_RACK_TRAY_LEAK: &str = "RackLeakDetectTray";
const POINT_TYPE_RACK_LIQUID_ISOLATION_REQUEST: &str = "RackLiquidIsolationRequest";
const POINT_TYPE_RACK_ELECTRICAL_ISOLATION_REQUEST: &str = "RackElectricalIsolationRequest";
const POINT_TYPE_HEARTBEAT_TIMESTAMP_INTEGRATION: &str = "HeartbeatTimestampIntegration";

#[derive(Debug, thiserror::Error)]
pub enum BmsDsxExchangeError {
    #[error("failed to parse metadata: {0}")]
    InvalidMetadata(#[from] serde_json::Error),

    #[error("metadata for point type `{point_type}` is missing `{field}` or empty")]
    MissingMetadataField {
        point_type: String,
        field: &'static str,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BinaryState {
    Inactive,
    Active,
}

impl From<bool> for BinaryState {
    fn from(value: bool) -> Self {
        if value { Self::Active } else { Self::Inactive }
    }
}

impl Serialize for BinaryState {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            Self::Inactive => serializer.serialize_i64(0),
            Self::Active => serializer.serialize_i64(1),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RackPointMetadata {
    RackTrayLeak {
        rack_name: String,
        rack_id: String,
        integration: String,
        value_topic: String,
    },
    LiquidIsolationRequest {
        rack_name: String,
        rack_id: String,
        integration: String,
        value_topic: String,
    },
    ElectricalIsolationRequest {
        rack_name: String,
        rack_id: String,
        integration: String,
        value_topic: String,
    },
}

impl RackPointMetadata {
    pub fn point_type(&self) -> &'static str {
        match self {
            Self::RackTrayLeak { .. } => POINT_TYPE_RACK_TRAY_LEAK,
            Self::LiquidIsolationRequest { .. } => POINT_TYPE_RACK_LIQUID_ISOLATION_REQUEST,
            Self::ElectricalIsolationRequest { .. } => POINT_TYPE_RACK_ELECTRICAL_ISOLATION_REQUEST,
        }
    }

    pub fn rack_id(&self) -> &str {
        match self {
            Self::RackTrayLeak { rack_id, .. }
            | Self::LiquidIsolationRequest { rack_id, .. }
            | Self::ElectricalIsolationRequest { rack_id, .. } => rack_id,
        }
    }

    pub fn integration(&self) -> &str {
        match self {
            Self::RackTrayLeak { integration, .. }
            | Self::LiquidIsolationRequest { integration, .. }
            | Self::ElectricalIsolationRequest { integration, .. } => integration,
        }
    }

    pub fn value_topic(&self) -> &str {
        match self {
            Self::RackTrayLeak { value_topic, .. }
            | Self::LiquidIsolationRequest { value_topic, .. }
            | Self::ElectricalIsolationRequest { value_topic, .. } => value_topic,
        }
    }

    pub fn source_id(&self) -> SourceId {
        SourceId::from_rack_metadata(self)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeartbeatMetadata {
    pub integration: String,
    pub value_topic: String,
}

impl HeartbeatMetadata {
    pub fn point_type(&self) -> &'static str {
        POINT_TYPE_HEARTBEAT_TIMESTAMP_INTEGRATION
    }

    pub fn source_id(&self) -> SourceId {
        SourceId::from_heartbeat_metadata(self)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SupportedMetadata {
    Rack(RackPointMetadata),
    Heartbeat(HeartbeatMetadata),
}

impl SupportedMetadata {
    pub fn integration(&self) -> &str {
        match self {
            Self::Rack(metadata) => metadata.integration(),
            Self::Heartbeat(metadata) => &metadata.integration,
        }
    }

    pub fn value_topic(&self) -> &str {
        match self {
            Self::Rack(metadata) => metadata.value_topic(),
            Self::Heartbeat(metadata) => &metadata.value_topic,
        }
    }

    pub fn point_type(&self) -> &str {
        match self {
            Self::Rack(metadata) => metadata.point_type(),
            Self::Heartbeat(metadata) => metadata.point_type(),
        }
    }

    pub fn source_id(&self) -> SourceId {
        match self {
            Self::Rack(metadata) => metadata.source_id(),
            Self::Heartbeat(metadata) => metadata.source_id(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValueMessage {
    pub value: SourceValue,
    pub timestamp: i64,
    pub quality: String,
}

impl ValueMessage {
    pub fn new(value: SourceValue, timestamp: i64) -> Self {
        Self {
            value,
            timestamp,
            quality: GOOD_QUALITY.to_string(),
        }
    }
}

impl Serialize for ValueMessage {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut map = serializer.serialize_map(Some(3))?;
        map.serialize_entry("value", &self.value)?;
        map.serialize_entry("timestamp", &self.timestamp)?;
        map.serialize_entry("quality", &self.quality)?;
        map.end()
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawMetadata {
    point_type: String,
    object_type: String,
    #[serde(default)]
    rack_name: Option<String>,
    #[serde(default)]
    rack_id: Option<String>,
    #[serde(default)]
    value_topic: Option<String>,
    #[serde(default)]
    integration: Option<String>,
}

pub fn parse_supported_metadata(
    input: impl AsRef<str>,
) -> Result<Option<SupportedMetadata>, BmsDsxExchangeError> {
    parse_supported_metadata_slice(input.as_ref().as_bytes())
}

pub fn parse_supported_metadata_slice(
    input: &[u8],
) -> Result<Option<SupportedMetadata>, BmsDsxExchangeError> {
    let raw: RawMetadata = serde_json::from_slice(input)?;
    required_field(&raw.point_type, "objectType", Some(raw.object_type.clone()))?;
    required_field(&raw.point_type, "pointType", Some(raw.point_type.clone()))?;
    SupportedMetadata::from_raw(raw)
}

impl SupportedMetadata {
    fn from_raw(raw: RawMetadata) -> Result<Option<Self>, BmsDsxExchangeError> {
        let value_topic = || required_field(&raw.point_type, "valueTopic", raw.value_topic.clone());
        let integration =
            || required_field(&raw.point_type, "integration", raw.integration.clone());
        let rack_name = || required_field(&raw.point_type, "rackName", raw.rack_name.clone());
        let rack_id = || required_field(&raw.point_type, "rackId", raw.rack_id.clone());

        match (raw.object_type.as_str(), raw.point_type.as_str()) {
            (OBJECT_TYPE_RACK, POINT_TYPE_RACK_LIQUID_ISOLATION_REQUEST) => Ok(Some(Self::Rack(
                RackPointMetadata::LiquidIsolationRequest {
                    rack_name: rack_name()?,
                    rack_id: rack_id()?,
                    integration: integration()?,
                    value_topic: value_topic()?,
                },
            ))),
            (OBJECT_TYPE_RACK, POINT_TYPE_RACK_ELECTRICAL_ISOLATION_REQUEST) => Ok(Some(
                Self::Rack(RackPointMetadata::ElectricalIsolationRequest {
                    rack_name: rack_name()?,
                    rack_id: rack_id()?,
                    integration: integration()?,
                    value_topic: value_topic()?,
                }),
            )),
            (OBJECT_TYPE_SYSTEM, POINT_TYPE_HEARTBEAT_TIMESTAMP_INTEGRATION) => {
                Ok(Some(Self::Heartbeat(HeartbeatMetadata {
                    integration: integration()?,
                    value_topic: value_topic()?,
                })))
            }
            _ => Ok(None),
        }
    }
}

fn required_field(
    point_type: &str,
    field: &'static str,
    value: Option<String>,
) -> Result<String, BmsDsxExchangeError> {
    let value = value.ok_or_else(|| BmsDsxExchangeError::MissingMetadataField {
        point_type: point_type.to_string(),
        field,
    })?;

    if value.trim().is_empty() {
        return Err(BmsDsxExchangeError::MissingMetadataField {
            point_type: point_type.to_string(),
            field,
        });
    }

    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_rack_metadata() {
        let metadata = parse_supported_metadata(
            r#"{
                "pointType": "RackLiquidIsolationRequest",
                "objectType": "Rack",
                "rackName": "Rack-01",
                "rackId": "rack-01",
                "integration": "CM",
                "valueTopic": "BMS/v1/CM/Value/Rack/RackLiquidIsolationRequest/site/rack-01"
            }"#,
        )
        .unwrap()
        .unwrap();

        assert_eq!(
            metadata.point_type(),
            POINT_TYPE_RACK_LIQUID_ISOLATION_REQUEST
        );
        assert_eq!(metadata.integration(), "CM");
    }

    #[test]
    fn serializes_value_message() {
        let message =
            ValueMessage::new(SourceValue::Binary(BinaryState::Active), 1_712_345_678_901);

        let json = serde_json::to_value(message).unwrap();
        assert_eq!(
            json,
            serde_json::json!({
                "value": 1,
                "timestamp": 1_712_345_678_901_i64,
                "quality": "1"
            })
        );
    }

    #[test]
    fn parses_heartbeat_metadata() {
        let metadata = parse_supported_metadata(
            r#"{
                "pointType": "HeartbeatTimestampIntegration",
                "objectType": "System",
                "integration": "CM",
                "valueTopic": "BMS/v1/CM/Value/System/HeartbeatTimestampIntegration/site"
            }"#,
        )
        .unwrap()
        .unwrap();

        assert_eq!(
            metadata.point_type(),
            POINT_TYPE_HEARTBEAT_TIMESTAMP_INTEGRATION
        );
        assert_eq!(metadata.integration(), "CM");
        assert_eq!(
            metadata.value_topic(),
            "BMS/v1/CM/Value/System/HeartbeatTimestampIntegration/site"
        );
    }

    #[test]
    fn rejects_supported_metadata_empty_required_field() {
        let error = parse_supported_metadata(
            r#"{
                "pointType": "RackLiquidIsolationRequest",
                "objectType": "Rack",
                "rackName": "Rack-01",
                "rackId": "rack-01",
                "integration": "",
                "valueTopic": "BMS/v1/CM/Value/Rack/RackLiquidIsolationRequest/site/rack-01"
            }"#,
        )
        .unwrap_err();

        assert!(matches!(
            error,
            BmsDsxExchangeError::MissingMetadataField {
                field: "integration",
                ..
            }
        ));
    }
}
