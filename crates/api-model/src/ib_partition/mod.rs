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

use std::str::FromStr;

use config_version::ConfigVersion;
use serde::{Deserialize, Serialize};

use crate::StateSla;

mod slas;

/// Represents an InfiniBand Partition Key
/// Partition Keys are 16 bit values valid up to a value of 0x7fff
/// Partition Keys are serialized as strings, since the hex represenation is
/// their canonical representation.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub struct PartitionKey(u16);

impl PartitionKey {
    /// Returns the partition key associated with the default partition
    pub const fn for_default_partition() -> Self {
        Self(0x7fff)
    }

    /// Returns whether the partition key describes the default partition
    pub fn is_default_partition(self) -> bool {
        self == Self::for_default_partition()
    }
}

#[derive(thiserror::Error, Debug, Clone)]
#[error("Partition Key \"{0}\" is not valid")]
pub struct InvalidPartitionKeyError(String);

impl serde::Serialize for PartitionKey {
    fn serialize<S>(&self, s: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.to_string().serialize(s)
    }
}

impl<'de> serde::Deserialize<'de> for PartitionKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::Error;
        let str_value = String::deserialize(deserializer)?;
        let version =
            PartitionKey::from_str(&str_value).map_err(|err| Error::custom(err.to_string()))?;
        Ok(version)
    }
}

impl TryFrom<u16> for PartitionKey {
    type Error = InvalidPartitionKeyError;

    fn try_from(pkey: u16) -> Result<Self, Self::Error> {
        if pkey != (pkey & 0x7fff) {
            return Err(InvalidPartitionKeyError(pkey.to_string()));
        }

        Ok(PartitionKey(pkey))
    }
}

impl FromStr for PartitionKey {
    type Err = InvalidPartitionKeyError;

    fn from_str(pkey: &str) -> Result<Self, Self::Err> {
        let pkey = pkey.to_lowercase();
        let base = if pkey.starts_with("0x") { 16 } else { 10 };
        let p = pkey.trim_start_matches("0x");
        let k = u16::from_str_radix(p, base);

        match k {
            Ok(v) => Ok(PartitionKey(v)),
            Err(_e) => Err(InvalidPartitionKeyError(pkey.to_string())),
        }
    }
}

impl TryFrom<String> for PartitionKey {
    type Error = InvalidPartitionKeyError;

    fn try_from(pkey: String) -> Result<Self, Self::Error> {
        PartitionKey::from_str(&pkey)
    }
}

impl TryFrom<&String> for PartitionKey {
    type Error = InvalidPartitionKeyError;

    fn try_from(pkey: &String) -> Result<Self, Self::Error> {
        PartitionKey::try_from(pkey.to_string())
    }
}

impl TryFrom<&str> for PartitionKey {
    type Error = InvalidPartitionKeyError;

    fn try_from(pkey: &str) -> Result<Self, Self::Error> {
        PartitionKey::try_from(pkey.to_string())
    }
}

impl std::fmt::Display for PartitionKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        write!(f, "0x{:x}", self.0)
    }
}

impl From<PartitionKey> for u16 {
    fn from(v: PartitionKey) -> u16 {
        v.0
    }
}

/// State of a IB subnet as tracked by the controller
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "lowercase")]
pub enum IBPartitionControllerState {
    /// The IB subnet is created in Carbide, waiting for provisioning in IB Fabric.
    Provisioning,
    /// The IB subnet is ready for IB ports.
    Ready,
    /// There is error in IB subnet; IB ports can not be added into IB subnet if it's error.
    Error { cause: String },
    /// The IB subnet is in the process of deleting.
    Deleting,
}

/// Returns the SLA for the current state
pub fn state_sla(state: &IBPartitionControllerState, state_version: &ConfigVersion) -> StateSla {
    let time_in_state = chrono::Utc::now()
        .signed_duration_since(state_version.timestamp())
        .to_std()
        .unwrap_or(std::time::Duration::from_secs(60 * 60 * 24));

    match state {
        IBPartitionControllerState::Provisioning => {
            StateSla::with_sla(slas::PROVISIONING, time_in_state)
        }
        IBPartitionControllerState::Ready => StateSla::no_sla(),
        IBPartitionControllerState::Error { .. } => StateSla::no_sla(),
        IBPartitionControllerState::Deleting => StateSla::with_sla(slas::DELETING, time_in_state),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serialize_and_format_pkey() {
        let pkey = PartitionKey::from_str("0xf").unwrap();
        let serialized = serde_json::to_string(&pkey).unwrap();
        assert_eq!(serialized, "\"0xf\"");
        assert_eq!(pkey.to_string(), "0xf");
        let deserialized = serde_json::from_str(&serialized).unwrap();
        assert_eq!(pkey, deserialized);
        let deserialized = serde_json::from_str("\"15\"").unwrap();
        assert_eq!(pkey, deserialized);
        let deserialized = serde_json::from_str("\"0xf\"").unwrap();
        assert_eq!(pkey, deserialized);
    }

    #[test]
    fn serialize_controller_state() {
        let state = IBPartitionControllerState::Provisioning {};
        let serialized = serde_json::to_string(&state).unwrap();
        assert_eq!(serialized, "{\"state\":\"provisioning\"}");
        assert_eq!(
            serde_json::from_str::<IBPartitionControllerState>(&serialized).unwrap(),
            state
        );
        let state = IBPartitionControllerState::Ready {};
        let serialized = serde_json::to_string(&state).unwrap();
        assert_eq!(serialized, "{\"state\":\"ready\"}");
        assert_eq!(
            serde_json::from_str::<IBPartitionControllerState>(&serialized).unwrap(),
            state
        );
        let state = IBPartitionControllerState::Error {
            cause: "cause goes here".to_string(),
        };
        let serialized = serde_json::to_string(&state).unwrap();
        assert_eq!(serialized, r#"{"state":"error","cause":"cause goes here"}"#);
        assert_eq!(
            serde_json::from_str::<IBPartitionControllerState>(&serialized).unwrap(),
            state
        );
        let state = IBPartitionControllerState::Deleting {};
        let serialized = serde_json::to_string(&state).unwrap();
        assert_eq!(serialized, "{\"state\":\"deleting\"}");
        assert_eq!(
            serde_json::from_str::<IBPartitionControllerState>(&serialized).unwrap(),
            state
        );
    }
}
