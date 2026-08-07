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

use super::{IpmiOps, RedfishOps};

/// Runtime-owned operation context supplied to a stateless driver.
pub struct OpCx<'a> {
    redfish: &'a dyn RedfishOps,
    ipmi: Option<&'a dyn IpmiOps>,
}

impl<'a> OpCx<'a> {
    pub fn new(redfish: &'a dyn RedfishOps) -> Self {
        Self {
            redfish,
            ipmi: None,
        }
    }

    pub fn with_ipmi(mut self, ipmi: &'a dyn IpmiOps) -> Self {
        self.ipmi = Some(ipmi);
        self
    }

    pub fn redfish(&self) -> &'a dyn RedfishOps {
        self.redfish
    }

    pub fn ipmi(&self) -> Option<&'a dyn IpmiOps> {
        self.ipmi
    }
}

#[cfg(test)]
mod tests {
    use std::pin::Pin;

    use async_trait::async_trait;
    use nv_redfish::core::query::{ExpandQuery, FilterQuery};
    use nv_redfish::core::{ModificationResponse, MultipartUpdateRequest, UploadReader};
    use nv_redfish::update_service::MultipartUpdateParameters;
    use serde_json::Value;

    use super::*;
    use crate::PlatformError;
    use crate::transport::{PatchCondition, RedfishResponse, RedfishUri};

    struct FakeTransport;

    #[async_trait]
    impl RedfishOps for FakeTransport {
        async fn get(&self, _uri: &RedfishUri) -> Result<RedfishResponse, PlatformError> {
            panic!("not used")
        }

        async fn expand(
            &self,
            _uri: &RedfishUri,
            _query: &ExpandQuery,
        ) -> Result<RedfishResponse, PlatformError> {
            panic!("not used")
        }

        async fn filter(
            &self,
            _uri: &RedfishUri,
            _query: &FilterQuery,
        ) -> Result<RedfishResponse, PlatformError> {
            panic!("not used")
        }

        async fn patch(
            &self,
            _uri: &RedfishUri,
            _body: &Value,
            _condition: &PatchCondition,
        ) -> Result<ModificationResponse<Value>, PlatformError> {
            panic!("not used")
        }

        async fn post(
            &self,
            _uri: &RedfishUri,
            _body: &Value,
        ) -> Result<ModificationResponse<Value>, PlatformError> {
            panic!("not used")
        }

        async fn delete(
            &self,
            _uri: &RedfishUri,
        ) -> Result<ModificationResponse<Value>, PlatformError> {
            panic!("not used")
        }

        async fn multipart_update(
            &self,
            _uri: &RedfishUri,
            _request: MultipartUpdateRequest<
                '_,
                Pin<Box<dyn UploadReader>>,
                MultipartUpdateParameters,
            >,
        ) -> Result<ModificationResponse<Value>, PlatformError> {
            panic!("not used")
        }
    }

    #[async_trait]
    impl IpmiOps for FakeTransport {
        async fn bmc_cold_reset(&self) -> Result<(), PlatformError> {
            Ok(())
        }

        async fn chassis_power_reset(&self) -> Result<(), PlatformError> {
            Ok(())
        }

        async fn dpu_legacy_power_reset(&self) -> Result<(), PlatformError> {
            Ok(())
        }
    }

    #[test]
    fn operation_context_exposes_optional_ipmi_transport() {
        let transport = FakeTransport;

        let redfish_only = OpCx::new(&transport);
        assert!(redfish_only.ipmi().is_none());

        let with_ipmi = OpCx::new(&transport).with_ipmi(&transport);
        assert!(with_ipmi.ipmi().is_some());
    }
}
