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
use std::fmt::Write;
use std::str::FromStr as _;

use ::rpc::admin_cli::OutputFormat;
use ::rpc::forge as forgerpc;
use carbide_uuid::domain::DomainId;
use carbide_uuid::network::NetworkSegmentId;
use prettytable::{Table, row};
use serde::Deserialize;

use super::args::Args;
use crate::errors::{CarbideCliError, CarbideCliResult};
use crate::rpc::ApiClient;

#[derive(Deserialize)]
struct NetworkState {
    state: String,
}

#[allow(deprecated)]
fn convert_old_history(
    history: &[forgerpc::NetworkSegmentStateHistory],
) -> Vec<forgerpc::StateHistoryRecord> {
    history
        .iter()
        .map(|h| forgerpc::StateHistoryRecord {
            state: h.state.clone(),
            version: h.version.clone(),
            time: h.time,
        })
        .collect()
}

#[allow(deprecated)]
async fn convert_network_to_nice_format(
    segment: forgerpc::NetworkSegment,
    history: Vec<forgerpc::StateHistoryRecord>,
    api_client: &ApiClient,
) -> CarbideCliResult<String> {
    let name = segment
        .metadata
        .as_ref()
        .map(|m| m.name.clone())
        .unwrap_or_else(|| segment.name.clone());

    let config = if let Some(config) = segment.config {
        config
    } else {
        // Old server: construct from deprecated flat fields.
        forgerpc::NetworkSegmentConfig {
            vpc_id: segment.vpc_id,
            subdomain_id: segment.subdomain_id,
            mtu: segment.mtu,
            segment_type: segment.segment_type,
            prefixes: segment.prefixes.clone(),
        }
    };

    let state = if let Some(lc) = segment.status.and_then(|s| s.lifecycle) {
        serde_json::from_str::<NetworkState>(&lc.state)
            .map(|ns| ns.state)
            .unwrap_or_else(|_| lc.state)
    } else {
        // Old server: format the deprecated enum field as a string.
        format!(
            "{:?}",
            forgerpc::TenantState::try_from(segment.state).unwrap_or_default()
        )
    };

    let width = 10;
    let mut lines = String::new();

    let data = vec![
        (
            "ID",
            segment.id.map(|id| id.to_string()).unwrap_or_default(),
        ),
        ("NAME", name),
        ("CREATED", segment.created.unwrap_or_default().to_string()),
        ("UPDATED", segment.updated.unwrap_or_default().to_string()),
        (
            "DELETED",
            segment
                .deleted
                .map(|x| x.to_string())
                .unwrap_or("Not Deleted".to_string()),
        ),
        ("STATE", state),
        ("VPC", config.vpc_id.unwrap_or_default().to_string()),
        (
            "DOMAIN",
            format!(
                "{}/{}",
                config.subdomain_id.unwrap_or_default(),
                get_domain_name(config.subdomain_id, api_client).await
            ),
        ),
        (
            "TYPE",
            format!(
                "{:?}",
                forgerpc::NetworkSegmentType::try_from(config.segment_type).unwrap_or_default()
            ),
        ),
    ];
    for (key, value) in data {
        writeln!(&mut lines, "{key:<width$}: {value}")?;
    }

    writeln!(&mut lines, "{:<width$}: ", "PREFIXES")?;
    let width = 15;
    if config.prefixes.is_empty() {
        writeln!(&mut lines, "\tEMPTY")?;
    } else {
        for (i, prefix) in config.prefixes.into_iter().enumerate() {
            let range = ipnet::IpNet::from_str(&prefix.prefix)
                .map(|net| format!("{} - {}", net.network(), net.broadcast()))
                .unwrap_or_else(|_| "invalid prefix".to_string());
            let data = vec![
                ("SN", i.to_string()),
                ("ID", prefix.id.unwrap_or_default().to_string()),
                ("Prefix", prefix.prefix),
                ("Range", range),
                (
                    "Gateway",
                    prefix.gateway.unwrap_or_else(|| "Unknown".to_string()),
                ),
                ("SVI IP", prefix.svi_ip.unwrap_or_default()),
                ("Reserve First", prefix.reserve_first.to_string()),
                ("Free IP Count", prefix.free_ip_count.to_string()),
            ];

            for (key, value) in data {
                writeln!(&mut lines, "\t{key:<width$}: {value}")?;
            }
            writeln!(
                &mut lines,
                "\t------------------------------------------------------------"
            )?;
        }
    }

    writeln!(&mut lines, "STATE HISTORY: (Latest 5 only)")?;
    if history.is_empty() {
        writeln!(&mut lines, "\tEMPTY")?;
    } else {
        writeln!(
            &mut lines,
            "\tState          Version                      Time"
        )?;
        writeln!(
            &mut lines,
            "\t---------------------------------------------------"
        )?;
        for x in history.iter().rev().take(5).rev() {
            writeln!(
                &mut lines,
                "\t{:<15} {:25} {}",
                serde_json::from_str::<NetworkState>(&x.state)
                    .map(|ns| ns.state)
                    .unwrap_or_else(|_| x.state.clone()),
                x.version,
                x.time.unwrap_or_default()
            )?;
        }
    }

    Ok(lines)
}

async fn get_domain_name(domain_id: Option<DomainId>, api_client: &ApiClient) -> String {
    match domain_id {
        Some(id) => match api_client.get_domains(Some(id)).await {
            Ok(domain_list) => {
                let Some(first) = domain_list.domains.into_iter().next() else {
                    return "Not Found in db".to_string();
                };

                first.name
            }
            Err(x) => x.to_string(),
        },
        None => "NA".to_owned(),
    }
}

#[allow(deprecated)]
fn convert_network_to_nice_table(
    segments: forgerpc::NetworkSegmentList,
) -> CarbideCliResult<Box<Table>> {
    let mut table = Table::new();

    table.set_titles(row![
        "Id", "Name", "Created", "State", "Vpc ID", "MTU", "Prefixes", "Last IP", "Version",
        "Type",
    ]);

    for segment in segments.network_segments {
        let name = segment
            .metadata
            .as_ref()
            .map(|m| m.name.as_str())
            .unwrap_or(segment.name.as_str())
            .to_string();

        let config = if let Some(config) = segment.config {
            config
        } else {
            // Old server: construct from deprecated flat fields.
            forgerpc::NetworkSegmentConfig {
                vpc_id: segment.vpc_id,
                subdomain_id: segment.subdomain_id,
                mtu: segment.mtu,
                segment_type: segment.segment_type,
                prefixes: segment.prefixes.clone(),
            }
        };

        let (state, version) = if let Some(lc) = segment.status.and_then(|s| s.lifecycle) {
            let state = serde_json::from_str::<NetworkState>(&lc.state)
                .map(|ns| ns.state)
                .unwrap_or_else(|_| lc.state.clone());
            (state, lc.version)
        } else {
            // Old server: format deprecated enum and version fields.
            let state = format!(
                "{:?}",
                forgerpc::TenantState::try_from(segment.state).unwrap_or_default()
            );
            (state, segment.version.clone())
        };

        let Some(first_prefix) = config.prefixes.first() else {
            continue;
        };
        let Ok(net) = ipnet::IpNet::from_str(&first_prefix.prefix) else {
            continue;
        };
        let end_ip = net.broadcast().to_string();

        table.add_row(row![
            segment.id.unwrap_or_default(),
            name,
            segment.created.unwrap_or_default(),
            state,
            config.vpc_id.unwrap_or_default(),
            config.mtu.unwrap_or(-1),
            config
                .prefixes
                .iter()
                .map(|x| x.prefix.to_string())
                .collect::<Vec<String>>()
                .join(", "),
            end_ip,
            version,
            format!(
                "{:?}",
                forgerpc::NetworkSegmentType::try_from(config.segment_type).unwrap_or_default()
            ),
        ]);
    }

    Ok(table.into())
}

async fn show_all_segments(
    json: bool,
    api_client: &ApiClient,
    tenant_org_id: Option<String>,
    name: Option<String>,
    page_size: usize,
) -> CarbideCliResult<()> {
    let all_segments = match api_client
        .get_all_segments(tenant_org_id, name, page_size)
        .await
    {
        Ok(all_segment_ids) => all_segment_ids,
        Err(e) => return Err(e),
    };
    if json {
        println!("{}", serde_json::to_string_pretty(&all_segments)?);
    } else {
        convert_network_to_nice_table(all_segments)?.printstd();
    }
    Ok(())
}

async fn show_network_information(
    segment_id: NetworkSegmentId,
    json: bool,
    api_client: &ApiClient,
) -> CarbideCliResult<()> {
    let segment = match api_client.get_one_segment(segment_id).await {
        Ok(instances) => instances,
        Err(e) => return Err(e),
    };

    let Some(segment) = segment.network_segments.into_iter().next() else {
        return Err(CarbideCliError::SegmentNotFound);
    };

    // Try the `FindNetworkSegmentStateHistories` RPC first; fall back to the inline
    // history field populated by old servers that lack the new RPC.
    #[allow(deprecated)]
    let history = api_client
        .get_segment_state_history(segment_id)
        .await
        .ok()
        .filter(|r| !r.is_empty())
        .unwrap_or_else(|| convert_old_history(&segment.history));

    if json {
        println!("{}", serde_json::to_string_pretty(&segment)?);
    } else {
        println!(
            "{}",
            convert_network_to_nice_format(segment, history, api_client).await?
        );
    }
    Ok(())
}

pub async fn handle_show(
    args: Args,
    output_format: OutputFormat,
    api_client: &ApiClient,
    page_size: usize,
) -> CarbideCliResult<()> {
    let is_json = output_format == OutputFormat::Json;
    if let Some(network) = args.network {
        show_network_information(network, is_json, api_client).await?;
    } else {
        show_all_segments(
            is_json,
            api_client,
            args.tenant_org_id,
            args.name,
            page_size,
        )
        .await?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use ::rpc::forge as forgerpc;

    use super::{convert_network_to_nice_table, convert_old_history};

    fn prefix(cidr: &str) -> forgerpc::NetworkPrefix {
        forgerpc::NetworkPrefix {
            prefix: cidr.to_string(),
            id: None,
            gateway: None,
            reserve_first: 0,
            free_ip_count: 0,
            svi_ip: None,
        }
    }

    fn old_history_record(state: &str, version: &str) -> forgerpc::NetworkSegmentStateHistory {
        #[allow(deprecated)]
        forgerpc::NetworkSegmentStateHistory {
            state: state.to_string(),
            version: version.to_string(),
            time: None,
        }
    }

    // ---------- convert_old_history ----------
    //
    // `show_network_information` calls `get_segment_state_history` (new RPC) and falls back to
    // `convert_old_history(&segment.history)` when that RPC is unavailable or returns empty.
    // That full path cannot be unit-tested here because it requires an `ApiClient`. The test
    // below verifies the pure conversion function that the fallback delegates to.

    #[test]
    fn convert_old_history_preserves_fields() {
        let records = vec![
            old_history_record("Ready", "v1"),
            old_history_record("Provisioning", "v2"),
        ];
        let result = convert_old_history(&records);
        assert_eq!(result.len(), 2);
        assert_eq!(result[0].state, "Ready");
        assert_eq!(result[0].version, "v1");
        assert_eq!(result[1].state, "Provisioning");
        assert_eq!(result[1].version, "v2");
    }

    // ---------- convert_network_to_nice_table ----------

    // Simulates a response from a new server: new fields set, deprecated flat fields also set
    // (the server intentionally populates both for external client compatibility).
    fn new_format_segment(
        name: &str,
        vpc_uuid: &str,
        cidr: &str,
        state: &str,
    ) -> forgerpc::NetworkSegment {
        #[allow(deprecated)]
        forgerpc::NetworkSegment {
            id: None,
            config: Some(forgerpc::NetworkSegmentConfig {
                vpc_id: Some(vpc_uuid.parse().unwrap()),
                subdomain_id: None,
                mtu: Some(9000),
                segment_type: forgerpc::NetworkSegmentType::Tenant as i32,
                prefixes: vec![prefix(cidr)],
            }),
            status: Some(forgerpc::NetworkSegmentStatus {
                flags: vec![],
                lifecycle: Some(forgerpc::LifecycleStatus {
                    state: state.to_string(),
                    version: "2".to_string(),
                    state_reason: None,
                    sla: None,
                }),
                tenant_state: forgerpc::TenantState::Ready as i32,
            }),
            metadata: Some(forgerpc::Metadata {
                name: name.to_string(),
                description: String::new(),
                labels: vec![],
            }),
            // Deprecated flat fields still populated by the new server for backward compat.
            // These intentionally carry DIFFERENT values from the new fields so tests can
            // confirm the new fields take priority.
            name: format!("{name}-stale"),
            vpc_id: Some("11111111-1111-1111-1111-111111111111".parse().unwrap()),
            subdomain_id: None,
            mtu: Some(1500),
            prefixes: vec![prefix("192.0.2.0/24")],
            segment_type: forgerpc::NetworkSegmentType::Admin as i32,
            version: "old-version".to_string(),
            state: forgerpc::TenantState::Provisioning as i32,
            history: vec![],
            created: None,
            updated: None,
            deleted: None,
            flags: vec![],
            state_reason: None,
            state_sla: None,
        }
    }

    fn old_format_segment(name: &str, vpc_uuid: &str, cidr: &str) -> forgerpc::NetworkSegment {
        // Simulates a response from an old server: new fields absent, deprecated flat fields set.
        #[allow(deprecated)]
        forgerpc::NetworkSegment {
            id: None,
            config: None,
            status: None,
            metadata: None,
            name: name.to_string(),
            vpc_id: Some(vpc_uuid.parse().unwrap()),
            subdomain_id: None,
            mtu: Some(1500),
            prefixes: vec![prefix(cidr)],
            segment_type: forgerpc::NetworkSegmentType::Tenant as i32,
            version: "1".to_string(),
            state: forgerpc::TenantState::Ready as i32,
            history: vec![],
            created: None,
            updated: None,
            deleted: None,
            flags: vec![],
            state_reason: None,
            state_sla: None,
        }
    }

    fn table_string(segments: Vec<forgerpc::NetworkSegment>) -> String {
        let list = forgerpc::NetworkSegmentList {
            network_segments: segments,
        };
        let table = convert_network_to_nice_table(list).expect("table build failed");
        format!("{table}")
    }

    // When both new fields and deprecated flat fields are present (as a new server always sends),
    // the new fields must take priority.
    #[test]
    fn table_new_format_uses_new_fields_not_deprecated() {
        let out = table_string(vec![new_format_segment(
            "seg-new",
            "00000000-0000-0000-0000-000000000001",
            "10.0.0.0/24",
            "Ready",
        )]);
        // New name from metadata, not the stale "-stale" name in the flat field.
        assert!(out.contains("seg-new"), "name from metadata missing: {out}");
        assert!(
            !out.contains("seg-new-stale"),
            "stale deprecated name must not appear: {out}"
        );
        // State from status.lifecycle, not the deprecated TenantState::Provisioning.
        assert!(out.contains("Ready"), "state from lifecycle missing: {out}");
        assert!(
            !out.contains("Provisioning"),
            "stale deprecated state must not appear: {out}"
        );
        // VPC from config, not the stale flat field UUID.
        assert!(
            out.contains("00000000-0000-0000-0000-000000000001"),
            "vpc_id from config missing: {out}"
        );
        assert!(
            !out.contains("11111111-1111-1111-1111-111111111111"),
            "stale deprecated vpc_id must not appear: {out}"
        );
    }

    #[test]
    fn table_old_format_shows_name_and_state() {
        let out = table_string(vec![old_format_segment(
            "seg-old",
            "00000000-0000-0000-0000-000000000002",
            "10.1.0.0/24",
        )]);
        assert!(out.contains("seg-old"), "name missing: {out}");
        assert!(out.contains("Ready"), "state missing: {out}");
    }

    #[test]
    fn table_old_format_shows_vpc_id() {
        let vpc = "00000000-0000-0000-0000-000000000002";
        let out = table_string(vec![old_format_segment("s", vpc, "10.1.0.0/24")]);
        assert!(out.contains(vpc), "vpc_id missing: {out}");
    }

    #[test]
    fn table_old_and_new_format_both_shown() {
        let out = table_string(vec![
            new_format_segment(
                "seg-new",
                "00000000-0000-0000-0000-000000000001",
                "10.0.0.0/24",
                "Ready",
            ),
            old_format_segment(
                "seg-old",
                "00000000-0000-0000-0000-000000000002",
                "10.1.0.0/24",
            ),
        ]);
        assert!(out.contains("seg-new"), "new segment missing: {out}");
        assert!(out.contains("seg-old"), "old segment missing: {out}");
    }

    // Coverage gaps (require a live ApiClient and cannot be unit-tested here):
    //
    // - `convert_network_to_nice_format` with old-format segments: same old->new fallback logic
    //   as `convert_network_to_nice_table` but also looks up the domain name via the API.
    //
    // - `show_network_information` history fallback: when `get_segment_state_history` (new RPC)
    //   fails or returns empty, the code falls back to `convert_old_history(&segment.history)`.
    //   The conversion itself is tested above; the integration path needs an ApiClient mock.
    //
    // - `get_vpc_for_interface_network_segment` (instance/show): the `.or(s.vpc_id)` fallback
    //   for the deprecated flat vpc_id field also requires ApiClient.
    //
    // - `handle_overlay_segment_creation` (devenv/config/apply): the name and prefix fallbacks
    //   are inline in an async function that requires ApiClient.
}
