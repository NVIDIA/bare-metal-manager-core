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

use std::net::IpAddr;

use carbide_uuid::rack::RackId;
use db::db_read::DbReader;
use db::{self, DatabaseResult};

use crate::config::NvLinkConfig;

/// Default NMX-C gRPC port when switch NVOS info does not specify one.
pub const NMX_C_DEFAULT_GRPC_PORT: u16 = 9601;

fn nmx_c_endpoint_uses_tls(config: &NvLinkConfig) -> bool {
    config.nmx_c_tls_client_cert_path.is_some() && config.nmx_c_tls_client_key_path.is_some()
}

fn nmx_c_endpoint_scheme(config: &NvLinkConfig) -> &'static str {
    if config.allow_insecure && !nmx_c_endpoint_uses_tls(config) {
        "http"
    } else {
        "https"
    }
}

/// Builds an NMX-C gRPC URL from a switch NVOS IP (same data as RPC `SwitchNvosInfo`).
pub fn nmx_c_endpoint_url_from_nvos_ip(
    ip: &IpAddr,
    port: Option<u16>,
    config: &NvLinkConfig,
) -> String {
    format!(
        "{}://{}:{}",
        nmx_c_endpoint_scheme(config),
        ip,
        port.unwrap_or(NMX_C_DEFAULT_GRPC_PORT)
    )
}

/// Resolves the NMX-C gRPC endpoint URL for a chassis.
///
/// When `rack_id` is set and the rack has a ready switch with Fabric Manager control plane
/// configured, uses the first matching switch's NVOS IP. Otherwise falls back to
/// `nvlink_nmxc_endpoints` for `chassis_serial`.
pub async fn resolve_nmx_c_endpoint_url<DB>(
    db: &mut DB,
    rack_id: Option<&RackId>,
    chassis_serial: &str,
    nvlink_config: &NvLinkConfig,
) -> DatabaseResult<Option<String>>
where
    for<'db> &'db mut DB: DbReader<'db>,
{
    if let Some(rack_id) = rack_id {
        let switch_ids =
            db::switch::find_ready_control_plane_configured_switch_ids_in_rack(&mut *db, rack_id)
                .await?;

        if let Some(switch_id) = switch_ids.first() {
            let endpoint_rows =
                db::switch::find_switch_endpoints_by_ids(&mut *db, &[*switch_id]).await?;

            if let Some(nvos_ip) = endpoint_rows.first().and_then(|row| row.nvos_ip.as_ref()) {
                return Ok(Some(nmx_c_endpoint_url_from_nvos_ip(
                    nvos_ip,
                    None,
                    nvlink_config,
                )));
            }

            tracing::debug!(
                %rack_id,
                %switch_id,
                %chassis_serial,
                "Ready configured switch has no NVOS IP; falling back to nvlink_nmxc_endpoints"
            );
        }
    }

    Ok(
        db::nvlink_nmxc_endpoints::find_by_chassis_serial(&mut *db, chassis_serial.trim())
            .await?
            .map(|row| row.endpoint),
    )
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;

    #[test]
    fn endpoint_url_uses_http_when_allow_insecure() {
        let config = NvLinkConfig {
            allow_insecure: true,
            ..Default::default()
        };
        assert_eq!(
            nmx_c_endpoint_url_from_nvos_ip(&IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), None, &config),
            "http://10.0.0.1:9601"
        );
    }

    #[test]
    fn endpoint_url_uses_https_by_default() {
        let config = NvLinkConfig::default();
        assert_eq!(
            nmx_c_endpoint_url_from_nvos_ip(&IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), None, &config),
            "https://10.0.0.1:9601"
        );
    }
}
