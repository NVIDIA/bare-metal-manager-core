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

//! Applies the operator vendor pin to what `nv_redfish` reads.
//! It takes no forced vendor, so its service root is rewritten instead.

use std::future::Future;

use libredfish::model::service_root::RedfishVendor;
use nv_redfish::bmc_http::credentials::BmcCredentials;
use nv_redfish::bmc_http::reqwest::BmcError;
use nv_redfish::bmc_http::{HttpClient, MultipartUpdateRequest};
use nv_redfish::core::odata::ODataETag;
use nv_redfish::core::upload::UploadReader;
use nv_redfish::core::{BoxTryStream, ModificationResponse, SessionCreateResponse};
use reqwest::header::HeaderMap;
use serde::Serialize;
use serde::de::DeserializeOwned;
use url::Url;

/// What a pin writes into the service root vendor field.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum VendorWrite {
    Set(&'static str),
    /// Some platforms are recognized by the absence of a vendor.
    Remove,
}

/// The service root vendor a pin asserts, as `nv_redfish` spells it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PinnedIdentity {
    vendor: VendorWrite,
}

/// The vendor a pin asserts, or `None` to leave the service root untouched.
/// Only the vendor is written, so classification proceeds as it always would.
fn pinned_identity(pin: RedfishVendor) -> Option<PinnedIdentity> {
    let vendor = match pin {
        RedfishVendor::Dell => VendorWrite::Set("Dell"),
        RedfishVendor::Hpe => VendorWrite::Set("HPE"),
        RedfishVendor::AMI => VendorWrite::Set("AMI"),
        RedfishVendor::Lenovo | RedfishVendor::LenovoAMI | RedfishVendor::LenovoGB300 => {
            VendorWrite::Set("Lenovo")
        }
        RedfishVendor::Supermicro => VendorWrite::Set("Supermicro"),
        // BlueField reports the mixed case spelling, the rest report upper case.
        RedfishVendor::NvidiaDpu => VendorWrite::Set("Nvidia"),
        RedfishVendor::NvidiaGBx00
        | RedfishVendor::NvidiaGH200
        | RedfishVendor::VeraRubin
        | RedfishVendor::NvidiaGBSwitch
        | RedfishVendor::P3809 => VendorWrite::Set("NVIDIA"),
        // Both shelves present with no vendor, which is how they are recognized.
        RedfishVendor::LiteOnPowerShelf | RedfishVendor::DeltaPowerShelf => VendorWrite::Remove,
        // Sushy is a development emulator `nv_redfish` does not classify, so a
        // pin has no vendor to assert and the service root is left untouched.
        RedfishVendor::Sushy | RedfishVendor::Unknown => return None,
    };

    Some(PinnedIdentity { vendor })
}

impl PinnedIdentity {
    /// Rewrite the vendor on a fetched service root, in place.
    fn apply(self, body: &mut serde_json::Value) {
        let Some(root) = body.as_object_mut() else {
            return;
        };
        match self.vendor {
            VendorWrite::Set(vendor) => {
                root.insert("Vendor".to_string(), serde_json::Value::from(vendor));
            }
            VendorWrite::Remove => {
                root.remove("Vendor");
            }
        }
    }
}

/// True for the service root, the one response a pin rewrites.
fn is_service_root(url: &Url) -> bool {
    matches!(url.path(), "/redfish/v1" | "/redfish/v1/")
}

/// Wraps an HTTP client so the operator vendor pin reaches `nv_redfish`.
pub struct VendorPinnedHttpClient<C> {
    inner: C,
    identity: Option<PinnedIdentity>,
}

impl<C> VendorPinnedHttpClient<C> {
    pub fn new(inner: C, pin: Option<RedfishVendor>) -> Self {
        Self {
            inner,
            identity: pin.and_then(pinned_identity),
        }
    }
}

impl<C> HttpClient for VendorPinnedHttpClient<C>
where
    C: HttpClient<Error = BmcError>,
{
    type Error = BmcError;

    async fn get<T>(
        &self,
        url: Url,
        credentials: &BmcCredentials,
        etag: Option<ODataETag>,
        custom_headers: &HeaderMap,
    ) -> Result<T, Self::Error>
    where
        T: DeserializeOwned + Send + Sync,
    {
        let Some(identity) = self.identity.filter(|_| is_service_root(&url)) else {
            return self.inner.get(url, credentials, etag, custom_headers).await;
        };

        // Parsed twice, since `HttpClient` hands back a deserialized value rather
        // than bytes. Bounded to one document per pinned BMC per cache miss.
        let mut body: serde_json::Value = self
            .inner
            .get(url, credentials, etag, custom_headers)
            .await?;
        identity.apply(&mut body);
        serde_json::from_value(body).map_err(BmcError::DecodeError)
    }

    fn post<B, T>(
        &self,
        url: Url,
        body: &B,
        credentials: &BmcCredentials,
        custom_headers: &HeaderMap,
    ) -> impl Future<Output = Result<ModificationResponse<T>, Self::Error>> + Send
    where
        B: Serialize + Send + Sync,
        T: DeserializeOwned + Send + Sync,
    {
        self.inner.post(url, body, credentials, custom_headers)
    }

    fn post_session<B, T>(
        &self,
        url: Url,
        body: &B,
        custom_headers: &HeaderMap,
    ) -> impl Future<Output = Result<SessionCreateResponse<T>, Self::Error>> + Send
    where
        B: Serialize + Send + Sync,
        T: DeserializeOwned + Send + Sync,
    {
        self.inner.post_session(url, body, custom_headers)
    }

    fn post_multipart_update<U, V, T>(
        &self,
        url: Url,
        request: MultipartUpdateRequest<'_, U, V>,
        credentials: &BmcCredentials,
        custom_headers: &HeaderMap,
    ) -> impl Future<Output = Result<ModificationResponse<T>, Self::Error>> + Send
    where
        U: UploadReader,
        T: DeserializeOwned + Send + Sync,
        V: Serialize + Send + Sync,
    {
        self.inner
            .post_multipart_update(url, request, credentials, custom_headers)
    }

    fn patch<B, T>(
        &self,
        url: Url,
        etag: ODataETag,
        body: &B,
        credentials: &BmcCredentials,
        custom_headers: &HeaderMap,
    ) -> impl Future<Output = Result<ModificationResponse<T>, Self::Error>> + Send
    where
        B: Serialize + Send + Sync,
        T: DeserializeOwned + Send + Sync,
    {
        self.inner
            .patch(url, etag, body, credentials, custom_headers)
    }

    fn delete<T>(
        &self,
        url: Url,
        credentials: &BmcCredentials,
        custom_headers: &HeaderMap,
    ) -> impl Future<Output = Result<ModificationResponse<T>, Self::Error>> + Send
    where
        T: DeserializeOwned + Send + Sync,
    {
        self.inner.delete(url, credentials, custom_headers)
    }

    fn sse<T: Sized + for<'de> serde::Deserialize<'de> + Send>(
        &self,
        url: Url,
        credentials: &BmcCredentials,
        custom_headers: &HeaderMap,
    ) -> impl Future<Output = Result<BoxTryStream<T, Self::Error>, Self::Error>> + Send {
        self.inner.sse(url, credentials, custom_headers)
    }
}

#[cfg(test)]
mod tests {
    use carbide_test_support::value_scenarios;

    use super::*;

    fn root() -> serde_json::Value {
        serde_json::json!({
            "@odata.id": "/redfish/v1/",
            "Vendor": "AMI",
            "Product": "Some Product",
            "RedfishVersion": "1.15.1",
        })
    }

    fn applied(pin: RedfishVendor) -> serde_json::Value {
        let mut body = root();
        if let Some(identity) = pinned_identity(pin) {
            identity.apply(&mut body);
        }
        body
    }

    /// A pin names a vendor and nothing else, so every other field the BMC
    /// reported survives and `nv_redfish` classifies as it always would.
    #[test]
    fn a_rewritten_root_carries_the_pinned_vendor_and_nothing_else() {
        value_scenarios!(
            run = |pin: RedfishVendor| {
                let body = applied(pin);
                (
                    body.get("Vendor").and_then(|v| v.as_str()).map(str::to_string),
                    body.get("Product").and_then(|v| v.as_str()).map(str::to_string),
                    body.get("RedfishVersion").and_then(|v| v.as_str()).map(str::to_string),
                )
            };

            "a pinned vendor replaces the reported one" {
                RedfishVendor::Dell => (
                    Some("Dell".to_string()),
                    Some("Some Product".to_string()),
                    Some("1.15.1".to_string()),
                ),
                RedfishVendor::Hpe => (
                    Some("HPE".to_string()),
                    Some("Some Product".to_string()),
                    Some("1.15.1".to_string()),
                ),
                RedfishVendor::Supermicro => (
                    Some("Supermicro".to_string()),
                    Some("Some Product".to_string()),
                    Some("1.15.1".to_string()),
                ),
                RedfishVendor::AMI => (
                    Some("AMI".to_string()),
                    Some("Some Product".to_string()),
                    Some("1.15.1".to_string()),
                ),
            }

            "the three Lenovo pins share one wire spelling" {
                RedfishVendor::Lenovo => (
                    Some("Lenovo".to_string()),
                    Some("Some Product".to_string()),
                    Some("1.15.1".to_string()),
                ),
                RedfishVendor::LenovoAMI => (
                    Some("Lenovo".to_string()),
                    Some("Some Product".to_string()),
                    Some("1.15.1".to_string()),
                ),
                RedfishVendor::LenovoGB300 => (
                    Some("Lenovo".to_string()),
                    Some("Some Product".to_string()),
                    Some("1.15.1".to_string()),
                ),
            }

            "BlueField uses the mixed case spelling, the rest upper case" {
                RedfishVendor::NvidiaDpu => (
                    Some("Nvidia".to_string()),
                    Some("Some Product".to_string()),
                    Some("1.15.1".to_string()),
                ),
                RedfishVendor::NvidiaGBx00 => (
                    Some("NVIDIA".to_string()),
                    Some("Some Product".to_string()),
                    Some("1.15.1".to_string()),
                ),
                RedfishVendor::VeraRubin => (
                    Some("NVIDIA".to_string()),
                    Some("Some Product".to_string()),
                    Some("1.15.1".to_string()),
                ),
                RedfishVendor::NvidiaGH200 => (
                    Some("NVIDIA".to_string()),
                    Some("Some Product".to_string()),
                    Some("1.15.1".to_string()),
                ),
                RedfishVendor::NvidiaGBSwitch => (
                    Some("NVIDIA".to_string()),
                    Some("Some Product".to_string()),
                    Some("1.15.1".to_string()),
                ),
                RedfishVendor::P3809 => (
                    Some("NVIDIA".to_string()),
                    Some("Some Product".to_string()),
                    Some("1.15.1".to_string()),
                ),
            }

            "both shelves present with no vendor at all" {
                RedfishVendor::LiteOnPowerShelf => (
                    None,
                    Some("Some Product".to_string()),
                    Some("1.15.1".to_string()),
                ),
                RedfishVendor::DeltaPowerShelf => (
                    None,
                    Some("Some Product".to_string()),
                    Some("1.15.1".to_string()),
                ),
            }

            "an unusable pin leaves the root untouched" {
                RedfishVendor::Unknown => (
                    Some("AMI".to_string()),
                    Some("Some Product".to_string()),
                    Some("1.15.1".to_string()),
                ),
                RedfishVendor::Sushy => (
                    Some("AMI".to_string()),
                    Some("Some Product".to_string()),
                    Some("1.15.1".to_string()),
                ),
            }
        );
    }

    /// A malformed root must pass through rather than panic, since this runs in
    /// the HTTP path for pinned hosts.
    #[test]
    fn applying_a_pin_to_a_body_that_is_not_an_object_changes_nothing() {
        let identity = pinned_identity(RedfishVendor::Dell).expect("Dell rewrites");
        for mut body in [
            serde_json::json!([]),
            serde_json::json!("not a root"),
            serde_json::json!(null),
        ] {
            let before = body.clone();
            identity.apply(&mut body);
            assert_eq!(body, before, "a non object body must pass through");
        }
    }

    /// Removing a vendor that was never there has to be a no op, not a panic.
    #[test]
    fn removing_an_absent_vendor_is_tolerated() {
        let identity = pinned_identity(RedfishVendor::LiteOnPowerShelf).expect("LiteOn rewrites");
        let mut body = serde_json::json!({ "@odata.id": "/redfish/v1/" });
        identity.apply(&mut body);

        assert_eq!(body, serde_json::json!({ "@odata.id": "/redfish/v1/" }));
    }

    /// Only the service root is rewritten, so no other resource is touched.
    #[test]
    fn only_the_service_root_is_rewritten() {
        assert!(is_service_root(
            &Url::parse("https://bmc/redfish/v1").unwrap()
        ));
        assert!(is_service_root(
            &Url::parse("https://bmc/redfish/v1/").unwrap()
        ));
        assert!(!is_service_root(
            &Url::parse("https://bmc/redfish/v1/Systems").unwrap()
        ));
        assert!(!is_service_root(
            &Url::parse("https://bmc/redfish/v1/Chassis/1").unwrap()
        ));
    }
}
