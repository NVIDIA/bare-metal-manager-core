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

use std::fmt;
use std::pin::Pin;
use std::str::FromStr;

use async_trait::async_trait;
use http::{StatusCode, Uri};
use nv_redfish::core::query::{ExpandQuery, FilterQuery};
use nv_redfish::core::{ModificationResponse, MultipartUpdateRequest, ODataETag, UploadReader};
use nv_redfish::update_service::MultipartUpdateParameters;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::Value;
use thiserror::Error;

use crate::PlatformError;

/// A same-BMC Redfish URI with an optional query string.
///
/// Redfish task monitors can include query tokens in their `Location` header,
/// while normal resource and action URIs usually contain only a path. Origins,
/// fragments, traversal, and paths outside `/redfish/v1` are rejected.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct RedfishUri(String);

impl RedfishUri {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for RedfishUri {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl FromStr for RedfishUri {
    type Err = RedfishUriError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        if value.contains('#') {
            return Err(RedfishUriError::Fragment);
        }
        if value.contains('\\')
            || value
                .bytes()
                .any(|byte| byte.is_ascii_control() || byte == b' ')
        {
            return Err(RedfishUriError::InvalidCharacter);
        }
        let uri: Uri = value.parse().map_err(|_| RedfishUriError::InvalidUri)?;
        if uri.scheme().is_some() || uri.authority().is_some() {
            return Err(RedfishUriError::Origin);
        }
        let path = uri.path();
        if path != "/redfish/v1" && !path.starts_with("/redfish/v1/") {
            return Err(RedfishUriError::OutsideServiceRoot);
        }
        if path.contains("//") {
            return Err(RedfishUriError::EmptySegment);
        }
        let lower = path.to_ascii_lowercase();
        if path.split('/').any(|segment| matches!(segment, "." | ".."))
            || lower.contains("%2e")
            || lower.contains("%2f")
            || lower.contains("%5c")
        {
            return Err(RedfishUriError::Traversal);
        }
        Ok(Self(value.to_owned()))
    }
}

impl Serialize for RedfishUri {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for RedfishUri {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        String::deserialize(deserializer)?
            .parse()
            .map_err(serde::de::Error::custom)
    }
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum RedfishUriError {
    #[error("Redfish URI is invalid")]
    InvalidUri,
    #[error("Redfish URI must not contain an origin")]
    Origin,
    #[error("Redfish URI must not contain a fragment")]
    Fragment,
    #[error("Redfish URI must be rooted at /redfish/v1")]
    OutsideServiceRoot,
    #[error("Redfish URI must not contain control characters, spaces, or backslashes")]
    InvalidCharacter,
    #[error("Redfish URI must not contain an empty path segment")]
    EmptySegment,
    #[error("Redfish URI must not contain traversal or encoded path separators")]
    Traversal,
}

/// The response data a driver needs from a raw Redfish GET.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RedfishResponse {
    pub status: StatusCode,
    pub etag: Option<ODataETag>,
    pub body: Option<Value>,
}

/// Conditional request policy for a Redfish PATCH operation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PatchCondition {
    /// Do not send an `If-Match` header.
    Unconditional,
    /// Send `If-Match: *`.
    IfMatchAny,
    /// Send `If-Match` with the supplied entity tag.
    IfMatch(ODataETag),
}

/// Restricted transport operations available to capability drivers.
#[async_trait]
pub trait RedfishOps: Send + Sync {
    async fn get(&self, uri: &RedfishUri) -> Result<RedfishResponse, PlatformError>;

    /// GET with a typed `$expand` query.
    ///
    /// Implementations preserve query parameters already present in `uri`.
    async fn expand(
        &self,
        uri: &RedfishUri,
        query: &ExpandQuery,
    ) -> Result<RedfishResponse, PlatformError>;

    /// GET with a typed `$filter` query.
    ///
    /// Implementations preserve query parameters already present in `uri`.
    async fn filter(
        &self,
        uri: &RedfishUri,
        query: &FilterQuery,
    ) -> Result<RedfishResponse, PlatformError>;

    async fn patch(
        &self,
        uri: &RedfishUri,
        body: &Value,
        condition: &PatchCondition,
    ) -> Result<ModificationResponse<Value>, PlatformError>;

    async fn post(
        &self,
        uri: &RedfishUri,
        body: &Value,
    ) -> Result<ModificationResponse<Value>, PlatformError>;

    async fn delete(&self, uri: &RedfishUri) -> Result<ModificationResponse<Value>, PlatformError>;

    async fn multipart_update(
        &self,
        uri: &RedfishUri,
        request: MultipartUpdateRequest<'_, Pin<Box<dyn UploadReader>>, MultipartUpdateParameters>,
    ) -> Result<ModificationResponse<Value>, PlatformError>;
}

#[cfg(test)]
mod tests {
    use carbide_test_support::Outcome::{Fails, Yields};
    use carbide_test_support::scenarios;

    use super::*;

    #[test]
    fn redfish_uris_enforce_transport_boundary_invariants() {
        scenarios!(run = |value: &str| value.parse::<RedfishUri>().map(|uri| uri.to_string());
            "valid BMC-relative URIs" {
                "/redfish/v1" => Yields("/redfish/v1".to_string()),
                "/redfish/v1/" => Yields("/redfish/v1/".to_string()),
                "/redfish/v1/Systems/1" => Yields("/redfish/v1/Systems/1".to_string()),
                "/redfish/v1/Systems?$expand=." =>
                    Yields("/redfish/v1/Systems?$expand=.".to_string()),
                "/redfish/v1/Systems/1/Actions/ComputerSystem.Reset" =>
                    Yields("/redfish/v1/Systems/1/Actions/ComputerSystem.Reset".to_string()),
                "/redfish/v1/Managers/BMC%201" =>
                    Yields("/redfish/v1/Managers/BMC%201".to_string()),
            }
            "origins and authorities are rejected" {
                "https://bmc/redfish/v1" => Fails,
                "//bmc/redfish/v1" => Fails,
                "redfish/v1/Systems/1" => Fails,
            }
            "fragments are rejected" {
                "/redfish/v1/Systems#member" => Fails,
            }
            "service-root lookalikes are rejected" {
                "/" => Fails,
                "/redfish" => Fails,
                "/redfish/v10" => Fails,
            }
            "ambiguous and traversing paths are rejected" {
                "/redfish/v1//Systems" => Fails,
                "/redfish/v1/../Managers" => Fails,
                "/redfish/v1/%2e%2e/Managers" => Fails,
                "/redfish/v1/Systems%2f1" => Fails,
                "/redfish/v1\\Systems" => Fails,
                "/redfish/v1/Systems 1" => Fails,
            }
        );
    }

    #[test]
    fn redfish_uris_validate_during_deserialization() {
        let uri: RedfishUri = serde_json::from_str("\"/redfish/v1/Systems/1?$select=Id\"")
            .expect("valid URI deserializes");
        assert_eq!(uri.as_str(), "/redfish/v1/Systems/1?$select=Id");
        assert!(serde_json::from_str::<RedfishUri>("\"https://bmc/redfish/v1\"").is_err());
    }

    #[test]
    fn redfish_uri_preserves_task_monitor_queries_without_allowing_an_origin() {
        let uri: RedfishUri = "/redfish/v1/TaskService/Tasks/42?token=opaque"
            .parse()
            .expect("same-BMC task URI is valid");
        assert_eq!(
            uri.as_str(),
            "/redfish/v1/TaskService/Tasks/42?token=opaque"
        );
        assert!(
            "https://other/redfish/v1/TaskService/Tasks/42"
                .parse::<RedfishUri>()
                .is_err()
        );
        assert!(
            "/redfish/v1/TaskService/Tasks/42#details"
                .parse::<RedfishUri>()
                .is_err()
        );
    }

    #[test]
    fn patch_condition_preserves_policy_distinctions() {
        let etag = ODataETag::from("\"revision-42\"".to_string());

        assert_ne!(PatchCondition::Unconditional, PatchCondition::IfMatchAny);
        assert_ne!(
            PatchCondition::IfMatchAny,
            PatchCondition::IfMatch(etag.clone())
        );
        assert_eq!(
            PatchCondition::IfMatch(etag.clone()),
            PatchCondition::IfMatch(etag)
        );
    }
}
