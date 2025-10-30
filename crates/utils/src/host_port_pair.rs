/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */
use std::fmt::{Display, Formatter};
use std::str::FromStr;

use serde::de::Visitor;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::host_port_pair::HostPortParseError::{
    EmptyString, InvalidPort, InvalidString, UriUnsupported,
};

/// A [`HostPortPair`] is a representation of a string like `some-host.fqdn:1234`.
///
/// It represents invariants that either the host must be set, or the port, or both. It is distinct
/// from a URI because there cases where (a) we don't want to specify a scheme, and (b) we don't
/// want to specify anything else like path/etc.
#[derive(PartialEq, Eq, Debug, Clone)]
pub enum HostPortPair {
    HostOnly(String),
    PortOnly(u16),
    HostAndPort(String, u16),
}

impl HostPortPair {
    pub fn host(&self) -> Option<&str> {
        match self {
            HostPortPair::PortOnly(_) => None,
            HostPortPair::HostOnly(h) | HostPortPair::HostAndPort(h, _) => Some(h.as_str()),
        }
    }

    pub fn port(&self) -> Option<u16> {
        match self {
            HostPortPair::HostOnly(_) => None,
            HostPortPair::PortOnly(p) | HostPortPair::HostAndPort(_, p) => Some(*p),
        }
    }
}

impl FromStr for HostPortPair {
    type Err = HostPortParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.contains("://") {
            return Err(UriUnsupported);
        }

        match s.split(":").collect::<Vec<_>>().as_slice() {
            [h, p] => {
                let p = p.parse::<u16>().map_err(|_| InvalidPort(p.to_string()))?;

                if h.is_empty() {
                    Ok(HostPortPair::PortOnly(p))
                } else {
                    Ok(HostPortPair::HostAndPort(h.to_string(), p))
                }
            }
            [h] => {
                if h.is_empty() {
                    Err(EmptyString)
                } else {
                    Ok(HostPortPair::HostOnly(h.to_string()))
                }
            }
            _ => Err(InvalidString),
        }
    }
}

impl Display for HostPortPair {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            HostPortPair::HostOnly(h) => write!(f, "{h}"),
            HostPortPair::PortOnly(p) => write!(f, "{p}"),
            HostPortPair::HostAndPort(h, p) => write!(f, "{h}:{p}"),
        }
    }
}

impl Serialize for HostPortPair {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.to_string().as_str())
    }
}

impl<'de> Deserialize<'de> for HostPortPair {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_str(HostPortPairVisitor)
    }
}

struct HostPortPairVisitor;
impl Visitor<'_> for HostPortPairVisitor {
    type Value = HostPortPair;

    fn expecting(&self, formatter: &mut Formatter) -> std::fmt::Result {
        write!(formatter, "A host:port string")
    }

    fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Self::Value::from_str(v)
            .map_err(|e| serde::de::Error::custom(format!("Invalid host-port pair: {e}")))
    }
}

#[derive(thiserror::Error, PartialEq, Eq, Debug)]
pub enum HostPortParseError {
    #[error("is a URI, only host:port strings are supported")]
    UriUnsupported,
    #[error("empty string")]
    EmptyString,
    #[error("Invalid port: {0}")]
    InvalidPort(String),
    #[error("Invalid string")]
    InvalidString,
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use crate::host_port_pair::{HostPortPair, HostPortParseError};

    #[test]
    fn test_proxy_address_parsing() {
        assert_eq!(
            HostPortPair::from_str("proxyhost:1234"),
            Ok(HostPortPair::HostAndPort("proxyhost".to_string(), 1234))
        );
        assert_eq!(
            HostPortPair::from_str("proxyhost"),
            Ok(HostPortPair::HostOnly("proxyhost".to_string()))
        );
        assert_eq!(
            HostPortPair::from_str(":1234"),
            Ok(HostPortPair::PortOnly(1234))
        );
        assert!(matches!(
            HostPortPair::from_str("proxyhost:"),
            Err(HostPortParseError::InvalidPort(_)),
        ));
        assert!(matches!(
            HostPortPair::from_str("proxyhost:notaport"),
            Err(HostPortParseError::InvalidPort(_)),
        ));
        assert!(matches!(
            HostPortPair::from_str(""),
            Err(HostPortParseError::EmptyString),
        ));
        assert!(matches!(
            HostPortPair::from_str("https://proxyhost:notaport"),
            Err(HostPortParseError::UriUnsupported),
        ));
        assert!(matches!(
            HostPortPair::from_str("https://proxyhost:1234"),
            Err(HostPortParseError::UriUnsupported),
        ));
        assert!(matches!(
            HostPortPair::from_str("https://proxyhost"),
            Err(HostPortParseError::UriUnsupported),
        ));
    }
}
