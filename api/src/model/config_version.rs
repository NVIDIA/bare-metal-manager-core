/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2023 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */

use std::{
    ops::{Deref, DerefMut},
    str::FromStr,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use chrono::{DateTime, NaiveDateTime, Utc};

/// A value that is accompanied by a version field
///
/// This small wrapper is intended to pass around any kind of value and the
/// associated version as a single parameter.
#[derive(Debug, Clone)]
pub struct Versioned<T> {
    /// The value that is versioned
    pub value: T,
    /// The value that is associated with this version
    pub version: ConfigVersion,
}

impl<T> Versioned<T> {
    /// Creates a new a `Versioned` wrapper around the value
    pub fn new(value: T, version: ConfigVersion) -> Self {
        Self { value, version }
    }

    /// Converts a `Versioned<T>` into a `Versioned<&T>`
    ///
    /// This is helpful to pass around versioned data cheaply (without having to
    /// deep copy it).
    pub fn as_ref(&self) -> Versioned<&T> {
        Versioned::new(&self.value, self.version)
    }
}

impl<T> Deref for Versioned<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.value
    }
}

impl<T> DerefMut for Versioned<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.value
    }
}

/// The version of any configuration that is applied in the Forge system
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct ConfigVersion {
    /// A monotonically incrementing number that alone uniquely identify the version
    /// of a configuration.
    version_nr: u64,
    /// A timestamp that is updated on each version number increment.
    /// This one mainly helps with observability: If we ever detect some
    /// subsytem dealing with an outdated configuration, we at least know when
    /// it last updated its configuration and how much it is behind.
    timestamp: DateTime<Utc>,
}

impl std::fmt::Display for ConfigVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Note that we could implement `to_version_string()` in terms of `Display`.
        // However this could mean that someone changing the Rust debug format
        // might accidentally touch the DB format. Therefore we keep a separate
        // method for this, and delegate the other way around.
        let version_str = self.to_version_string();
        f.write_str(&version_str)
    }
}

impl ConfigVersion {
    /// Returns the version number
    ///
    /// This is a monotonically incrementing number that is increased by each
    /// change to an entity
    pub fn version_nr(&self) -> u64 {
        self.version_nr
    }

    /// Returns the timestamp when the version was changed
    pub fn timestamp(&self) -> DateTime<Utc> {
        self.timestamp
    }

    /// Creates an initial version number for any entity
    pub fn initial() -> Self {
        Self {
            version_nr: 1,
            timestamp: now(),
        }
    }

    /// Increments the version
    ///
    /// This returns a new `ConfigVersion` instance, which carries the updated
    /// version number.
    pub fn increment(&self) -> Self {
        Self {
            version_nr: self.version_nr + 1,
            timestamp: now(),
        }
    }

    /// Returns a serialized format of `ConfigVersion`
    ///
    /// This is the database format we are using. Do not modify
    pub fn to_version_string(&self) -> String {
        // Note that we use microseconds here to get a reasonable precision
        // while being able to represent 584k years
        format!(
            "V{}-T{}",
            self.version_nr,
            self.timestamp.timestamp_micros()
        )
    }
}

/// Returns the current timestamp rounded to the next microsecond
///
/// We use this method since we only serialize the timestamp using microsecond
/// precision, and we don't want to have the timestamp look different after a
/// serialization and deserialization cycle.
fn now() -> DateTime<Utc> {
    let mut now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time before Unix epoch");
    let round = now.as_nanos() % 1000;
    now -= Duration::from_nanos(round as _);

    let naive = NaiveDateTime::from_timestamp_opt(now.as_secs() as i64, now.subsec_nanos())
        .expect("out-of-range number of seconds and/or invalid nanosecond");
    DateTime::from_utc(naive, Utc)
}

/// Error that is returned when parsing a version fails
#[derive(Debug, thiserror::Error)]
pub enum ParseConfigVersionError {
    #[error("Invalid version format: {0}")]
    InvalidVersionFormat(String),
    #[error("Invalid date time: {0}, {1}")]
    InvalidDateTime(i64, u32),
}

impl FromStr for ConfigVersion {
    type Err = ParseConfigVersionError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut parts = s.trim().split('-');

        let version_nr_str = match parts.next() {
            Some(nr_str) => nr_str,
            None => return Err(ParseConfigVersionError::InvalidVersionFormat(s.to_string())),
        };

        let timestamp_str = match parts.next() {
            Some(timestamp_str) => timestamp_str,
            None => return Err(ParseConfigVersionError::InvalidVersionFormat(s.to_string())),
        };

        if parts.next().is_some() {
            return Err(ParseConfigVersionError::InvalidVersionFormat(s.to_string()));
        }

        if version_nr_str.as_bytes().is_empty()
            || version_nr_str.as_bytes()[0] != b'V'
            || timestamp_str.as_bytes().is_empty()
            || timestamp_str.as_bytes()[0] != b'T'
        {
            return Err(ParseConfigVersionError::InvalidVersionFormat(s.to_string()));
        }

        let version_nr: u64 = version_nr_str[1..]
            .parse()
            .map_err(|_| ParseConfigVersionError::InvalidVersionFormat(s.to_string()))?;
        let timestamp: u64 = timestamp_str[1..]
            .parse()
            .map_err(|_| ParseConfigVersionError::InvalidVersionFormat(s.to_string()))?;

        let secs = timestamp / 1_000_000;
        let usecs = timestamp % 1_000_000;

        let datetime = match NaiveDateTime::from_timestamp_opt(secs as i64, (usecs * 1000) as u32) {
            Some(ndt) => ndt,
            None => {
                return Err(ParseConfigVersionError::InvalidDateTime(
                    secs as i64,
                    (usecs * 1000) as u32,
                ))
            }
        };

        let timestamp = DateTime::from_utc(datetime, Utc);

        Ok(Self {
            version_nr,
            timestamp,
        })
    }
}

impl serde::Serialize for ConfigVersion {
    fn serialize<S>(&self, s: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.to_version_string().serialize(s)
    }
}

impl<'de> serde::Deserialize<'de> for ConfigVersion {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::Error;
        let str_value = String::deserialize(deserializer)?;
        let version =
            ConfigVersion::from_str(&str_value).map_err(|err| Error::custom(err.to_string()))?;
        Ok(version)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serialize_and_deserialize_config_version_as_string() {
        let config_version = ConfigVersion::initial();
        let vs = config_version.to_version_string();
        let parsed: ConfigVersion = vs.parse().unwrap();
        assert_eq!(parsed, config_version);

        let next = config_version.increment();
        assert_eq!(next.version_nr, 2);
        let vs = next.to_version_string();
        let parsed_next: ConfigVersion = vs.parse().unwrap();
        assert_eq!(parsed_next, next);
    }

    #[test]
    fn serialize_and_deserialize_config_version_with_serde() {
        let config_version = ConfigVersion::initial();
        let vs = serde_json::to_string(&config_version).unwrap();
        let parsed: ConfigVersion = serde_json::from_str(&vs).unwrap();
        assert_eq!(parsed, config_version);

        let next = config_version.increment();
        assert_eq!(next.version_nr, 2);
        let vs = serde_json::to_string(&next).unwrap();
        let parsed_next: ConfigVersion = serde_json::from_str(&vs).unwrap();
        assert_eq!(parsed_next, next);
    }
}
