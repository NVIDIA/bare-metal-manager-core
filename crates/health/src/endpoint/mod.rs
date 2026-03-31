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

mod model;
mod sources;

pub use model::{
    BmcAddr, BmcCredentials, BmcEndpoint, BoxFuture, CredentialProvider, EndpointMetadata,
    EndpointSource, MachineData, SwitchData,
};
pub use sources::{CompositeEndpointSource, StaticEndpointSource};

#[cfg(test)]
mod tests {
    use std::str::FromStr;
    use std::sync::Arc;

    use mac_address::MacAddress;

    use super::*;
    use crate::HealthError;
    use crate::config::StaticBmcEndpoint;

    fn make_test_endpoint(mac: MacAddress) -> BmcEndpoint {
        BmcEndpoint::with_fixed_credentials(
            BmcAddr {
                ip: "10.0.0.1".parse().unwrap(),
                port: Some(443),
                mac,
            },
            BmcCredentials::UsernamePassword {
                username: "admin".to_string(),
                password: Some("password".to_string()),
            },
            None,
            None,
        )
    }

    #[tokio::test]
    async fn test_static_endpoint_source_shares_arc_data() {
        let endpoints = vec![
            make_test_endpoint(MacAddress::from_str("00:11:22:33:44:55").unwrap()),
            make_test_endpoint(MacAddress::from_str("aa:bb:cc:dd:ee:ff").unwrap()),
        ];
        let source = StaticEndpointSource::new(endpoints);

        let first = source.fetch_bmc_hosts().await.unwrap();
        let second = source.fetch_bmc_hosts().await.unwrap();

        assert_eq!(first.len(), 2);
        assert_eq!(second.len(), 2);
        assert!(Arc::ptr_eq(&first[0], &second[0]));
        assert!(Arc::ptr_eq(&first[1], &second[1]));
    }

    #[tokio::test]
    async fn test_composite_endpoint_source_preserves_arc_sharing() {
        let endpoints1 = vec![make_test_endpoint(
            MacAddress::from_str("00:11:22:33:44:55").unwrap(),
        )];
        let endpoints2 = vec![make_test_endpoint(
            MacAddress::from_str("aa:bb:cc:dd:ee:ff").unwrap(),
        )];

        let source1 = Arc::new(StaticEndpointSource::new(endpoints1));
        let source2 = Arc::new(StaticEndpointSource::new(endpoints2));

        let composite = CompositeEndpointSource::new(vec![source1.clone(), source2.clone()]);

        let composite_result = composite.fetch_bmc_hosts().await.unwrap();
        let source1_result = source1.fetch_bmc_hosts().await.unwrap();
        let source2_result = source2.fetch_bmc_hosts().await.unwrap();

        assert_eq!(composite_result.len(), 2);
        assert!(Arc::ptr_eq(&composite_result[0], &source1_result[0]));
        assert!(Arc::ptr_eq(&composite_result[1], &source2_result[0]));
    }

    #[test]
    fn test_to_url_uses_http_for_port_80_and_https_otherwise() {
        let addr_http = BmcAddr {
            ip: "10.0.0.1".parse().expect("valid ip"),
            port: Some(80),
            mac: MacAddress::from_str("00:11:22:33:44:55").unwrap(),
        };
        let addr_https = BmcAddr {
            ip: "10.0.0.2".parse().expect("valid ip"),
            port: Some(443),
            mac: MacAddress::from_str("aa:bb:cc:dd:ee:ff").unwrap(),
        };

        let url_http = addr_http.to_url().expect("url should build");
        let url_https = addr_https.to_url().expect("url should build");

        assert_eq!(url_http.scheme(), "http");
        assert_eq!(url_https.scheme(), "https");
    }

    #[tokio::test]
    async fn test_static_endpoint_source_filters_invalid_ip() {
        let configs = vec![
            StaticBmcEndpoint {
                ip: "10.0.0.1".to_string(),
                port: Some(443),
                mac: "00:11:22:33:44:55".to_string(),
                username: "admin".to_string(),
                password: Some("pass".to_string()),
                switch_serial: None,
                machine_id: None,
                rack_id: None,
            },
            StaticBmcEndpoint {
                ip: "not-an-ip".to_string(),
                port: Some(443),
                mac: "aa:bb:cc:dd:ee:ff".to_string(),
                username: "admin".to_string(),
                password: Some("pass".to_string()),
                switch_serial: None,
                machine_id: None,
                rack_id: None,
            },
        ];

        let source = StaticEndpointSource::from_config(&configs);
        let endpoints = source.fetch_bmc_hosts().await.expect("fetch should work");

        assert_eq!(endpoints.len(), 1);
        assert_eq!(
            endpoints[0].addr.mac,
            MacAddress::from_str("00:11:22:33:44:55").unwrap()
        );
    }

    #[tokio::test]
    async fn test_static_endpoint_with_switch_serial_sets_metadata() {
        let configs = vec![StaticBmcEndpoint {
            ip: "10.0.1.1".to_string(),
            port: Some(443),
            mac: "11:22:33:44:55:66".to_string(),
            username: "cumulus".to_string(),
            password: Some("pass".to_string()),
            switch_serial: Some("SN-001".to_string()),
            machine_id: None,
            rack_id: None,
        }];

        let source = StaticEndpointSource::from_config(&configs);
        let endpoints = source.fetch_bmc_hosts().await.unwrap();

        assert_eq!(endpoints.len(), 1);
        match &endpoints[0].metadata {
            Some(EndpointMetadata::Switch(s)) => assert_eq!(s.serial, "SN-001"),
            other => panic!("expected Switch metadata, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn test_static_endpoint_without_switch_serial_has_no_metadata() {
        let configs = vec![StaticBmcEndpoint {
            ip: "10.0.0.1".to_string(),
            port: Some(443),
            mac: "aa:bb:cc:dd:ee:ff".to_string(),
            username: "admin".to_string(),
            password: Some("pass".to_string()),
            switch_serial: None,
            machine_id: None,
            rack_id: None,
        }];

        let source = StaticEndpointSource::from_config(&configs);
        let endpoints = source.fetch_bmc_hosts().await.unwrap();

        assert_eq!(endpoints.len(), 1);
        assert!(endpoints[0].metadata.is_none());
    }

    struct FailingSource;

    impl EndpointSource for FailingSource {
        fn fetch_bmc_hosts<'a>(
            &'a self,
        ) -> BoxFuture<'a, Result<Vec<Arc<BmcEndpoint>>, HealthError>> {
            Box::pin(async {
                Err(HealthError::GenericError(
                    "simulated endpoint source failure".to_string(),
                ))
            })
        }
    }

    #[tokio::test]
    async fn test_composite_endpoint_source_propagates_errors() {
        let source_ok = Arc::new(StaticEndpointSource::new(vec![make_test_endpoint(
            MacAddress::from_str("00:11:22:33:44:55").unwrap(),
        )]));
        let source_fail = Arc::new(FailingSource);
        let composite = CompositeEndpointSource::new(vec![source_ok, source_fail]);

        let result = composite.fetch_bmc_hosts().await;

        assert!(result.is_err());
    }
}
