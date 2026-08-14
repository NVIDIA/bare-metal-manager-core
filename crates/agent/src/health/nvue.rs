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

use std::collections::BTreeMap;

use health_report::HealthReport;
use nvue_client::types::bgp::{BgpPeerInfo, BgpPeerState, BgpVrfInfo};

use super::{failed, make_alert, probe_ids};
use crate::HBNDeviceNames;

/// Checks configured ToR BGP sessions from an already-fetched NVUE BGP VRF response.
///
/// All configured HBN uplinks are evaluated, and the check passes when at least
/// `min_healthy_links` of them are present and established. If too few uplinks
/// are healthy, each missing peer, missing state, or non-established state emits
/// a `BgpPeeringTor` alert targeted at that uplink. A `BgpPeeringTor` alert is
/// emitted when `min_healthy_links` asks for more uplinks than the configured
/// device names provide. The helper does not emit success entries.
#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "Reusable NVUE BGP health helper is intentionally not wired yet"
    )
)]
pub(super) fn check_bgp_uplink_sessions(
    report: &mut HealthReport,
    bgp: &BgpVrfInfo,
    min_healthy_links: usize,
    hbn_device_names: &HBNDeviceNames,
) {
    let mut unhealthy_uplink_names = Vec::new();
    let mut healthy_uplink_count = 0;
    let expected_hbn_uplinks = hbn_device_names.uplinks.iter().copied();

    for expected_uplink in expected_hbn_uplinks {
        match check_expected_peer_established(bgp.neighbor.as_ref(), expected_uplink) {
            Ok(()) => healthy_uplink_count += 1,
            Err(message) => unhealthy_uplink_names.push((expected_uplink.to_string(), message)),
        }
    }

    if healthy_uplink_count >= min_healthy_links {
        return;
    }

    if min_healthy_links > hbn_device_names.uplinks.len() {
        failed(
            report,
            probe_ids::BgpPeeringTor.clone(),
            None,
            format!(
                "Site configuration requires a minimum of {min_healthy_links} \
                healthy uplinks, but this is greater than the number of \
                expected uplink interface names ({hbn_uplink_names})",
                hbn_uplink_names = hbn_device_names.uplinks.join(",")
            ),
        );
    }

    // This behavior differs from what the non-NVUE code path does (in
    // BgpHealthData::into_health_report()), in that we always treat this
    // case as critical. I couldn't make sense of why the other path computes
    // criticality like this:
    //
    // let num_unhealthy_tors = self.unhealthy_tor_peers.len();
    // // TODO: This is correct for environments with both DPU ports connected
    // let unhealthy_tors_critical = num_unhealthy_tors > 1;
    //
    // This looks like a duplication of what I think min_healthy_links is
    // concerned with, and also seems to hardcode an assumption about uplink
    // count.
    //
    // It was all added before The Big Squash so I couldn't learn anything from
    // the git history of the file.
    // - drew
    let is_critical = true;
    for (uplink, message) in unhealthy_uplink_names {
        report.alerts.push(make_alert(
            probe_ids::BgpPeeringTor.clone(),
            Some(uplink),
            message,
            is_critical,
        ));
    }
}

/// Checks whether an expected peer has an established NVUE BGP session.
///
/// Returns `Ok(())` when the peer exists in the NVUE neighbor map and reports
/// `BgpPeerState::Established`. A missing NVUE neighbor map, missing peer,
/// missing state, or non-established state returns a descriptive error message
/// for conversion to a health alert by the caller.
#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "Reusable NVUE BGP health helper is intentionally not wired yet"
    )
)]
fn check_expected_peer_established(
    neighbors: Option<&BTreeMap<String, BgpPeerInfo>>,
    peer_name: &str,
) -> Result<(), String> {
    let Some(neighbors) = neighbors else {
        return Err(format!(
            "BGP neighbor data was not reported; expected session for {peer_name}"
        ));
    };
    let Some(peer) = neighbors.get(peer_name) else {
        return Err(format!(
            "expected session for {peer_name} was not found in BGP peer data"
        ));
    };
    let Some(peer_state) = peer.state.as_ref() else {
        return Err(format!("state field for {peer_name} peer is not present"));
    };
    match peer_state {
        BgpPeerState::Established => Ok(()),
        state => Err(format!(
            "BGP session {peer_name} is not Established, but in state {state:?}"
        )),
    }
}

#[cfg(test)]
mod tests {
    use carbide_test_support::{Check, check_values};

    use super::*;

    /// One `check_bgp_uplink_sessions` scenario and its exact expected alerts.
    struct Row {
        scenario: &'static str,
        bgp_json: &'static str,
        min_healthy_links: usize,
        expected_alerts: Vec<health_report::HealthProbeAlert>,
    }

    /// Builds a NVUE BGP VRF response from a compact scenario JSON fixture.
    fn bgp_vrf_info(bgp_json: &str) -> BgpVrfInfo {
        serde_json::from_str(bgp_json).expect("BGP VRF info should deserialize")
    }

    /// Builds a ToR peering alert with the same target and criticality rules as production.
    fn tor_alert(port: &str, message: &str, critical: bool) -> health_report::HealthProbeAlert {
        make_alert(
            probe_ids::BgpPeeringTor.clone(),
            Some(port.to_string()),
            message.to_string(),
            critical,
        )
    }

    /// Builds the site-configuration alert for impossible uplink thresholds.
    fn config_mismatch_alert(min_healthy_links: usize) -> health_report::HealthProbeAlert {
        make_alert(
            probe_ids::BgpPeeringTor.clone(),
            None,
            format!(
                "Site configuration requires a minimum of {min_healthy_links} healthy uplinks, but this is greater than the number of expected uplink interface names (p0_if,p1_if)"
            ),
            true,
        )
    }

    /// Orders alerts by `(id, target, message)` so table rows can stay readable.
    fn sort_alerts(alerts: &mut [health_report::HealthProbeAlert]) {
        alerts.sort_by(|a, b| (&a.id, &a.target, &a.message).cmp(&(&b.id, &b.target, &b.message)));
    }

    #[test]
    fn check_bgp_tor_sessions_emits_expected_alerts() {
        check_values(
            [
                Row {
                    scenario: "all configured uplinks established",
                    bgp_json: r#"
                    {
                        "neighbor": {
                            "p0_if": { "state": "established" },
                            "p1_if": { "state": "established" }
                        }
                    }
                    "#,
                    min_healthy_links: 2,
                    expected_alerts: vec![],
                },
                Row {
                    scenario: "missing neighbor map alerts for each configured uplink",
                    bgp_json: r#"{}"#,
                    min_healthy_links: 2,
                    expected_alerts: vec![
                        tor_alert(
                            "p0_if",
                            "BGP neighbor data was not reported; expected session for p0_if",
                            true,
                        ),
                        tor_alert(
                            "p1_if",
                            "BGP neighbor data was not reported; expected session for p1_if",
                            true,
                        ),
                    ],
                },
                Row {
                    scenario: "missing configured uplink targets that uplink",
                    bgp_json: r#"
                    {
                        "neighbor": {
                            "p0_if": { "state": "established" }
                        }
                    }
                    "#,
                    min_healthy_links: 2,
                    expected_alerts: vec![tor_alert(
                        "p1_if",
                        "expected session for p1_if was not found in BGP peer data",
                        true,
                    )],
                },
                Row {
                    scenario: "idle configured uplink alerts when below threshold",
                    bgp_json: r#"
                    {
                        "neighbor": {
                            "p0_if": { "state": "idle" },
                            "p1_if": { "state": "established" }
                        }
                    }
                    "#,
                    min_healthy_links: 2,
                    expected_alerts: vec![tor_alert(
                        "p0_if",
                        "BGP session p0_if is not Established, but in state Idle",
                        true,
                    )],
                },
                Row {
                    scenario: "another non-established state alerts",
                    bgp_json: r#"
                    {
                        "neighbor": {
                            "p0_if": { "state": "active" },
                            "p1_if": { "state": "established" }
                        }
                    }
                    "#,
                    min_healthy_links: 2,
                    expected_alerts: vec![tor_alert(
                        "p0_if",
                        "BGP session p0_if is not Established, but in state Active",
                        true,
                    )],
                },
                Row {
                    scenario: "missing state alerts",
                    bgp_json: r#"
                    {
                        "neighbor": {
                            "p0_if": {},
                            "p1_if": { "state": "established" }
                        }
                    }
                    "#,
                    min_healthy_links: 2,
                    expected_alerts: vec![tor_alert(
                        "p0_if",
                        "state field for p0_if peer is not present",
                        true,
                    )],
                },
                Row {
                    scenario: "extra non-ToR and route-server neighbors ignored",
                    bgp_json: r#"
                    {
                        "neighbor": {
                            "p0_if": { "state": "established" },
                            "p1_if": { "state": "established" },
                            "tenant-vrf-peer": { "state": "idle" },
                            "10.217.126.67": { "state": "active" }
                        }
                    }
                    "#,
                    min_healthy_links: 2,
                    expected_alerts: vec![],
                },
                Row {
                    scenario: "one healthy uplink may be the second configured uplink",
                    bgp_json: r#"
                    {
                        "neighbor": {
                            "p0_if": { "state": "idle" },
                            "p1_if": { "state": "established" }
                        }
                    }
                    "#,
                    min_healthy_links: 1,
                    expected_alerts: vec![],
                },
                Row {
                    scenario: "min healthy links greater than configured uplinks alerts",
                    bgp_json: r#"
                    {
                        "neighbor": {
                            "p0_if": { "state": "established" },
                            "p1_if": { "state": "established" }
                        }
                    }
                    "#,
                    min_healthy_links: 3,
                    expected_alerts: vec![config_mismatch_alert(3)],
                },
            ]
            .map(|mut row| {
                sort_alerts(&mut row.expected_alerts);
                let expect = row.expected_alerts.clone();
                Check {
                    scenario: row.scenario,
                    input: row,
                    expect,
                }
            }),
            |row| {
                let mut hr = HealthReport::empty("forge-dpu-agent".to_string());
                check_bgp_uplink_sessions(
                    &mut hr,
                    &bgp_vrf_info(row.bgp_json),
                    row.min_healthy_links,
                    &HBNDeviceNames::hbn_23(),
                );
                sort_alerts(&mut hr.alerts);
                hr.alerts
            },
        );
    }
}
