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

//! Render one machine's boot-interface view (the `GetMachineBootInterfaces`
//! RPC) as an ASCII table, JSON, or YAML. The view gathers the four stores a
//! host's boot interface can live in -- owned interface rows, predictions, the
//! explored endpoint default, and the retained post-deletion pairs -- plus the
//! effective boot interface the system would select and a divergence flag.

use std::fmt::Write as _;

use ::rpc::admin_cli::OutputFormat;
use ::rpc::forge as forgerpc;
use carbide_uuid::machine::MachineId;
use prettytable::{Cell, Row, Table};
use serde::Serialize;

use super::args::Args;
use crate::errors::CarbideCliResult;
use crate::rpc::ApiClient;

/// The admin-cli-side projection of `GetMachineBootInterfacesResponse`, shaped
/// for clean JSON/YAML and for table rendering. Built straight from the proto
/// response, whose nullable boot-interface fields already carry absence as
/// `Option<String>` (proto3 field presence).
#[derive(Debug, Serialize)]
struct BootInterfacesReport {
    machine_id: Option<MachineId>,
    machine_interfaces: Vec<OwnedRow>,
    predicted_interfaces: Vec<PredictedRow>,
    explored_endpoints: Vec<ExploredRow>,
    retained_interfaces: Vec<RetainedRow>,
    /// MAC the system would boot from now (`pick_boot_interface` over the owned
    /// rows). `None` when there is no owned candidate yet.
    effective_boot_interface_mac: Option<String>,
    /// The fully-populated effective boot interface id, when captured.
    effective_boot_interface_id: Option<String>,
    /// True when the stores disagree about which MAC boots this machine.
    divergent: bool,
}

#[derive(Debug, Serialize)]
struct OwnedRow {
    mac_address: String,
    primary_interface: bool,
    boot_interface_id: Option<String>,
    network_segment_type: Option<String>,
}

#[derive(Debug, Serialize)]
struct PredictedRow {
    mac_address: String,
    primary_interface: bool,
    boot_interface_id: Option<String>,
    network_segment_type: Option<String>,
}

#[derive(Debug, Serialize)]
struct ExploredRow {
    address: String,
    boot_interface_mac: Option<String>,
    boot_interface_id: Option<String>,
}

#[derive(Debug, Serialize)]
struct RetainedRow {
    mac_address: String,
    boot_interface_id: String,
    recorded_at: Option<String>,
}

impl From<forgerpc::GetMachineBootInterfacesResponse> for BootInterfacesReport {
    fn from(r: forgerpc::GetMachineBootInterfacesResponse) -> Self {
        BootInterfacesReport {
            machine_id: r.machine_id,
            machine_interfaces: r
                .machine_interfaces
                .into_iter()
                .map(|i| OwnedRow {
                    mac_address: i.mac_address,
                    primary_interface: i.primary_interface,
                    boot_interface_id: i.boot_interface_id,
                    network_segment_type: i.network_segment_type,
                })
                .collect(),
            predicted_interfaces: r
                .predicted_interfaces
                .into_iter()
                .map(|p| PredictedRow {
                    mac_address: p.mac_address,
                    primary_interface: p.primary_interface,
                    boot_interface_id: p.boot_interface_id,
                    network_segment_type: p.network_segment_type,
                })
                .collect(),
            explored_endpoints: r
                .explored_endpoints
                .into_iter()
                .map(|e| ExploredRow {
                    address: e.address,
                    boot_interface_mac: e.boot_interface_mac,
                    boot_interface_id: e.boot_interface_id,
                })
                .collect(),
            retained_interfaces: r
                .retained_interfaces
                .into_iter()
                .map(|t| RetainedRow {
                    mac_address: t.mac_address,
                    boot_interface_id: t.boot_interface_id,
                    recorded_at: t.recorded_at.map(|ts| ts.to_string()),
                })
                .collect(),
            effective_boot_interface_mac: r.effective_boot_interface_mac,
            effective_boot_interface_id: r.effective_boot_interface_id,
            divergent: r.divergent,
        }
    }
}

pub async fn handle_boot_interfaces(
    args: Args,
    output_format: OutputFormat,
    api_client: &ApiClient,
) -> CarbideCliResult<()> {
    let response = api_client.get_machine_boot_interfaces(args.machine).await?;
    let report = BootInterfacesReport::from(response);

    match output_format {
        OutputFormat::Json => {
            println!("{}", serde_json::to_string_pretty(&report)?);
        }
        OutputFormat::Yaml => {
            println!("{}", serde_yaml::to_string(&report)?);
        }
        // CSV is a poor fit for a multi-section report; AsciiTable is the
        // human-readable form. Both render the same tables.
        OutputFormat::AsciiTable | OutputFormat::Csv => {
            print!("{}", render_tables(&report));
        }
    }
    Ok(())
}

/// One labeled table per store, then a summary block with the effective boot
/// interface and the divergence flag.
fn render_tables(report: &BootInterfacesReport) -> String {
    let mut out = String::new();
    let dash = |s: &Option<String>| s.as_deref().unwrap_or("-").to_string();

    let machine_id = report
        .machine_id
        .map(|id| id.to_string())
        .unwrap_or_default();
    let _ = writeln!(out, "Boot interfaces for machine {machine_id}");

    // Store 1: owned interface rows (authoritative for an owned machine).
    let _ = writeln!(out, "\nmachine_interfaces (owned rows):");
    let mut owned = Table::new();
    owned.set_titles(Row::new(
        [
            "MAC Address",
            "Primary",
            "Boot Interface Id",
            "Segment Type",
        ]
        .into_iter()
        .map(Cell::new)
        .collect(),
    ));
    if report.machine_interfaces.is_empty() {
        owned.add_row(Row::new(vec![Cell::new("(none)")]));
    } else {
        for i in &report.machine_interfaces {
            owned.add_row(Row::new(vec![
                Cell::new(&i.mac_address),
                Cell::new(&i.primary_interface.to_string()),
                Cell::new(&dash(&i.boot_interface_id)),
                Cell::new(&dash(&i.network_segment_type)),
            ]));
        }
    }
    let _ = write!(out, "{owned}");

    // Store 2: predictions (pre-first-lease candidates).
    let _ = writeln!(out, "\npredicted_machine_interfaces:");
    let mut predicted = Table::new();
    predicted.set_titles(Row::new(
        [
            "MAC Address",
            "Primary",
            "Boot Interface Id",
            "Segment Type",
        ]
        .into_iter()
        .map(Cell::new)
        .collect(),
    ));
    if report.predicted_interfaces.is_empty() {
        predicted.add_row(Row::new(vec![Cell::new("(none)")]));
    } else {
        for p in &report.predicted_interfaces {
            predicted.add_row(Row::new(vec![
                Cell::new(&p.mac_address),
                Cell::new(&p.primary_interface.to_string()),
                Cell::new(&dash(&p.boot_interface_id)),
                Cell::new(&dash(&p.network_segment_type)),
            ]));
        }
    }
    let _ = write!(out, "{predicted}");

    // Store 3: explored endpoint default (machine-less default; shown for the
    // machine's BMC endpoints).
    let _ = writeln!(out, "\nexplored_endpoints (default for unowned endpoints):");
    let mut explored = Table::new();
    explored.set_titles(Row::new(
        [
            "Endpoint Address",
            "Boot Interface MAC",
            "Boot Interface Id",
        ]
        .into_iter()
        .map(Cell::new)
        .collect(),
    ));
    if report.explored_endpoints.is_empty() {
        explored.add_row(Row::new(vec![Cell::new("(none)")]));
    } else {
        for e in &report.explored_endpoints {
            explored.add_row(Row::new(vec![
                Cell::new(&e.address),
                Cell::new(&dash(&e.boot_interface_mac)),
                Cell::new(&dash(&e.boot_interface_id)),
            ]));
        }
    }
    let _ = write!(out, "{explored}");

    // Store 4: retained post-deletion pairs (raw, including stale records).
    let _ = writeln!(
        out,
        "\nretained_boot_interfaces (post-deletion, incl. stale):"
    );
    let mut retained = Table::new();
    retained.set_titles(Row::new(
        ["MAC Address", "Boot Interface Id", "Recorded At"]
            .into_iter()
            .map(Cell::new)
            .collect(),
    ));
    if report.retained_interfaces.is_empty() {
        retained.add_row(Row::new(vec![Cell::new("(none)")]));
    } else {
        for t in &report.retained_interfaces {
            retained.add_row(Row::new(vec![
                Cell::new(&t.mac_address),
                Cell::new(&t.boot_interface_id),
                Cell::new(&dash(&t.recorded_at)),
            ]));
        }
    }
    let _ = write!(out, "{retained}");

    // Summary: the effective pick and the divergence flag.
    let _ = writeln!(
        out,
        "\nEffective boot interface MAC: {}",
        dash(&report.effective_boot_interface_mac)
    );
    let _ = writeln!(
        out,
        "Effective boot interface id:  {}",
        dash(&report.effective_boot_interface_id)
    );
    let _ = writeln!(out, "Stores diverge on boot MAC:   {}", report.divergent);

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A fixed report exercising every store, a captured pair, a stale retained
    /// record, a declared primary, and divergence.
    fn sample_report() -> BootInterfacesReport {
        BootInterfacesReport {
            machine_id: None,
            machine_interfaces: vec![OwnedRow {
                mac_address: "aa:bb:cc:00:00:01".to_string(),
                primary_interface: true,
                boot_interface_id: Some("NIC.Slot.1-1-1".to_string()),
                network_segment_type: Some("HostInband".to_string()),
            }],
            predicted_interfaces: vec![PredictedRow {
                mac_address: "aa:bb:cc:00:00:02".to_string(),
                primary_interface: false,
                boot_interface_id: None,
                network_segment_type: Some("Admin".to_string()),
            }],
            explored_endpoints: vec![ExploredRow {
                address: "10.0.0.5".to_string(),
                // A different NIC than the effective owned pick -> divergence.
                boot_interface_mac: Some("aa:bb:cc:00:00:09".to_string()),
                boot_interface_id: Some("NIC.Slot.9-1-1".to_string()),
            }],
            retained_interfaces: vec![RetainedRow {
                mac_address: "aa:bb:cc:00:00:03".to_string(),
                boot_interface_id: "NIC.Old.1-1-1".to_string(),
                recorded_at: Some("2026-06-01T00:00:00Z".to_string()),
            }],
            effective_boot_interface_mac: Some("aa:bb:cc:00:00:01".to_string()),
            effective_boot_interface_id: Some("NIC.Slot.1-1-1".to_string()),
            divergent: true,
        }
    }

    #[test]
    fn ascii_table_shows_each_store_and_summary() {
        let table = render_tables(&sample_report());

        // Section labels.
        assert!(table.contains("machine_interfaces (owned rows):"));
        assert!(table.contains("predicted_machine_interfaces:"));
        assert!(table.contains("explored_endpoints"));
        assert!(table.contains("retained_boot_interfaces"));

        // The boot_interface_id of the owned row.
        assert!(table.contains("NIC.Slot.1-1-1"));
        // The primary flag.
        assert!(table.contains("true"));
        // The retained record's recorded_at.
        assert!(table.contains("2026-06-01T00:00:00Z"));
        // The effective pick and divergence flag.
        assert!(table.contains("Effective boot interface MAC: aa:bb:cc:00:00:01"));
        assert!(table.contains("Stores diverge on boot MAC:   true"));
    }

    #[test]
    fn json_round_trips_with_every_field() {
        let json = serde_json::to_string_pretty(&sample_report()).expect("serialize json");

        // Field presence.
        assert!(json.contains("\"boot_interface_id\""));
        assert!(json.contains("NIC.Slot.1-1-1"));
        assert!(json.contains("\"recorded_at\""));
        assert!(json.contains("2026-06-01T00:00:00Z"));
        assert!(json.contains("\"primary_interface\": true"));
        assert!(json.contains("\"divergent\": true"));

        // Round-trips into a generic JSON value with the expected structure.
        let value: serde_json::Value = serde_json::from_str(&json).expect("parse json");
        assert_eq!(value["divergent"], serde_json::Value::Bool(true));
        assert_eq!(value["machine_interfaces"][0]["primary_interface"], true);
        assert_eq!(
            value["machine_interfaces"][0]["boot_interface_id"],
            "NIC.Slot.1-1-1"
        );
        assert_eq!(
            value["retained_interfaces"][0]["recorded_at"],
            "2026-06-01T00:00:00Z"
        );
        assert_eq!(value["effective_boot_interface_mac"], "aa:bb:cc:00:00:01");
    }

    #[test]
    fn yaml_round_trips_with_every_field() {
        let yaml = serde_yaml::to_string(&sample_report()).expect("serialize yaml");

        assert!(yaml.contains("boot_interface_id:"));
        assert!(yaml.contains("NIC.Slot.1-1-1"));
        assert!(yaml.contains("recorded_at:"));
        assert!(yaml.contains("divergent: true"));
        assert!(yaml.contains("primary_interface: true"));

        // Round-trips back into a generic YAML value.
        let value: serde_yaml::Value = serde_yaml::from_str(&yaml).expect("parse yaml");
        assert_eq!(value["divergent"], serde_yaml::Value::Bool(true));
        assert_eq!(
            value["retained_interfaces"][0]["recorded_at"],
            serde_yaml::Value::String("2026-06-01T00:00:00Z".to_string())
        );
    }

    /// The proto -> report conversion: absent fields (proto3 field presence,
    /// `None`) stay `None`, present ones pass through, and a `Timestamp`
    /// renders as RFC 3339.
    #[test]
    fn from_proto_response_maps_fields() {
        let response = forgerpc::GetMachineBootInterfacesResponse {
            machine_id: None,
            machine_interfaces: vec![forgerpc::MachineInterfaceBootInterface {
                mac_address: "aa:bb:cc:00:00:01".to_string(),
                primary_interface: true,
                boot_interface_id: Some("NIC.Slot.1-1-1".to_string()),
                network_segment_type: Some("HostInband".to_string()),
            }],
            predicted_interfaces: vec![],
            explored_endpoints: vec![forgerpc::ExploredBootInterface {
                address: "10.0.0.5".to_string(),
                // An absent boot MAC -> `None` in the report.
                boot_interface_mac: None,
                boot_interface_id: Some("NIC.Slot.9-1-1".to_string()),
            }],
            retained_interfaces: vec![forgerpc::RetainedBootInterface {
                mac_address: "aa:bb:cc:00:00:03".to_string(),
                boot_interface_id: "NIC.Old.1-1-1".to_string(),
                // The default Timestamp is the unix epoch; Display renders RFC 3339.
                recorded_at: Some(Default::default()),
            }],
            effective_boot_interface_mac: Some("aa:bb:cc:00:00:01".to_string()),
            // Absent -> `None`.
            effective_boot_interface_id: None,
            divergent: false,
        };

        let report = BootInterfacesReport::from(response);

        // Present values pass through; absent ones stay `None`.
        assert_eq!(
            report.machine_interfaces[0].boot_interface_id.as_deref(),
            Some("NIC.Slot.1-1-1")
        );
        assert!(report.machine_interfaces[0].primary_interface);
        assert_eq!(report.explored_endpoints[0].boot_interface_mac, None);
        assert_eq!(report.effective_boot_interface_id, None);
        assert_eq!(
            report.effective_boot_interface_mac.as_deref(),
            Some("aa:bb:cc:00:00:01")
        );
        // The Timestamp renders as an RFC 3339 string (epoch default here).
        assert_eq!(
            report.retained_interfaces[0].recorded_at.as_deref(),
            Some("1970-01-01T00:00:00Z")
        );
    }
}
