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

use std::collections::HashMap;

use serde::Deserialize;

use super::{failed, make_alert, passed, probe_ids};
use crate::{HBNDeviceNames, hbn};

/// Check HBN BGP stats
pub async fn check_bgp_stats(
    hr: &mut health_report::HealthReport,
    container_id: &str,
    host_routes: &[&str],
    min_healthy_links: u32,
    route_servers: &[String],
    hbn_device_names: HBNDeviceNames,
) {
    // If BGP daemon is not enabled, we will get a bunch of bogus alerts shown
    // that are not helpful to anyone. Since showing `BgpDaemonEnabled` already
    // covers the core problem - don't bother with the remaining checks.
    if hr
        .alerts
        .iter()
        .any(|alert| alert.id == *probe_ids::BgpDaemonEnabled)
    {
        return;
    }

    let mut health_data = BgpHealthData::default();

    // `vtysh` is the Free Range Routing (FRR) shell.
    match hbn::run_in_container(
        container_id,
        &["vtysh", "-c", "show bgp summary json"],
        true,
    )
    .await
    {
        Ok(bgp_json) => verify_bgp_summary(
            &mut health_data,
            &bgp_json,
            host_routes,
            min_healthy_links,
            route_servers,
            hbn_device_names,
        ),
        Err(err) => {
            tracing::warn!("check_network_stats show bgp summary: {err}");
            health_data.other_errors.push(err.to_string());
        }
    };

    health_data.into_health_report(hr);
}

pub fn check_daemon_enabled(hr: &mut health_report::HealthReport, hbn_daemons_file: &str) {
    let daemons = match std::fs::read_to_string(hbn_daemons_file) {
        Ok(s) => s,
        Err(err) => {
            tracing::warn!("check_bgp_daemon_enabled: {err}");
            failed(
                hr,
                probe_ids::BgpDaemonEnabled.clone(),
                None,
                format!("Trying to open and read {hbn_daemons_file}: {err}"),
            );
            return;
        }
    };

    if daemons.contains("bgpd=no") {
        failed(
            hr,
            probe_ids::BgpDaemonEnabled.clone(),
            None,
            format!("BGP daemon is disabled - {hbn_daemons_file} contains 'bgpd=no'"),
        );
        return;
    }
    if !daemons.contains("bgpd=yes") {
        failed(
            hr,
            probe_ids::BgpDaemonEnabled.clone(),
            None,
            format!("BGP daemon is not enabled - {hbn_daemons_file} does not contain 'bgpd=yes'"),
        );
        return;
    }

    passed(hr, probe_ids::BgpDaemonEnabled.clone(), None);
}

fn verify_bgp_summary(
    health_data: &mut BgpHealthData,
    bgp_json: &str,
    host_routes: &[&str],
    min_healthy_links: u32,
    route_servers: &[String],
    hbn_device_names: HBNDeviceNames,
) {
    let networks: BgpNetworks = match serde_json::from_str(bgp_json) {
        Ok(networks) => networks,
        Err(e) => {
            health_data.other_errors.push(format!(
                "failed to deserialize bgp_json: {bgp_json} with error: {e}"
            ));
            return;
        }
    };

    check_bgp_stats_ipv4_unicast(
        "ipv4_unicast",
        &networks.ipv4_unicast,
        health_data,
        host_routes,
        min_healthy_links,
        hbn_device_names.clone(),
    );
    check_bgp_stats_l2_vpn_evpn(
        "l2_vpn_evpn",
        &networks.l2_vpn_evpn,
        health_data,
        route_servers,
        min_healthy_links,
        hbn_device_names,
    );
}

fn check_bgp_tor_routes(
    s: &BgpStats,
    health_data: &mut BgpHealthData,
    min_healthy_links: u32,
    hbn_device_names: HBNDeviceNames,
) {
    for port_id in 0..min_healthy_links {
        let mut message = None;
        // The number of healthy links should never be above the total number of avail links
        let Some(port_name) = hbn_device_names
            .uplinks
            .get(port_id as usize)
            .map(|s| s.to_string())
        else {
            // This case should not happen, and will only happen if a configuration error at runtime is applied
            // such as having 7 min_healthy_links but we only have 2 ports
            health_data.other_errors.push(format!(
                "The number of min healthy links: {min_healthy_links} \
                was bigger than the number of uplinks defined by the hbn device names: {}",
                hbn_device_names.uplinks.len()
            ));
            return;
        };

        let session_data = s.peers.get(&port_name);
        match session_data {
            Some(session) => {
                if session.state != "Established" {
                    message = Some(format!(
                        "Session {port_name} is not Established, but in state {}",
                        session.state
                    ));
                }
            }
            None => {
                message = Some(format!(
                    "Expected session for {port_name} was not found in BGP peer data"
                ));
            }
        }

        if let Some(message) = message {
            health_data.unhealthy_tor_peers.insert(port_name, message);
        }
    }
}

fn check_bgp_stats_ipv4_unicast(
    name: &str,
    s: &BgpStats,
    health_data: &mut BgpHealthData,
    host_routes: &[&str],
    min_healthy_links: u32,
    hbn_device_names: HBNDeviceNames,
) {
    check_bgp_tor_routes(s, health_data, min_healthy_links, hbn_device_names);

    // We ignore the BPG sessions pointing towards tenant Machines
    // Tenants can choose to use or not use them.
    // However no other sessions are expected
    for (peer_name, _peer) in s.other_peers() {
        if !host_routes.contains(&peer_name.as_str()) {
            health_data
                .unexpected_peers
                .push((name.to_string(), peer_name.clone()));
        }
    }

    if s.dynamic_peers != 0 {
        health_data.other_errors.push(format!(
            "{name}.dynamic_peers is {} should be 0",
            s.dynamic_peers
        ));
    }
}

fn check_bgp_stats_l2_vpn_evpn(
    name: &str,
    s: &BgpStats,
    health_data: &mut BgpHealthData,
    route_servers: &[String],
    min_healthy_links: u32,
    hbn_device_names: HBNDeviceNames,
) {
    // In case Route servers are not specified, the peer list should contain only
    // TORs. Otherwise we expect it to contain the route servers.
    if route_servers.is_empty() {
        check_bgp_tor_routes(s, health_data, min_healthy_links, hbn_device_names);

        for (peer_name, _peer) in s.other_peers() {
            health_data
                .unexpected_peers
                .push((name.to_string(), peer_name.clone()));
        }
    } else {
        let mut other_peers: HashMap<&String, &BgpPeer> = s.other_peers().collect();
        for route_server in route_servers {
            let session_data = other_peers.remove(route_server);
            let mut message = None;
            match session_data {
                Some(session) => {
                    if session.state != "Established" {
                        message = Some(format!(
                            "Session {route_server} is not Established, but in state {}",
                            session.state
                        ));
                    }
                }
                None => {
                    message = Some(format!(
                        "Expected session for {route_server} was not found in BGP peer data"
                    ));
                }
            }

            if let Some(message) = message {
                health_data
                    .unhealthy_route_server_peers
                    .push((route_server.to_string(), message));
            }
        }

        for (peer_name, _peer) in other_peers {
            health_data
                .unexpected_peers
                .push((name.to_string(), peer_name.clone()));
        }
    }

    if s.dynamic_peers != 0 {
        health_data.other_errors.push(format!(
            "{name}.dynamic_peers is {} should be 0",
            s.dynamic_peers
        ));
    }
}

#[derive(Clone, Debug, Default)]
struct BgpHealthData {
    // Note that these are HashMaps because we check TOR connections in 2 places
    // and dedup the messages using the HashMap
    pub unhealthy_tor_peers: HashMap<String, String>,
    pub unhealthy_route_server_peers: Vec<(String, String)>,
    pub unexpected_peers: Vec<(String, String)>,
    pub other_errors: Vec<String>,
}

impl BgpHealthData {
    pub fn into_health_report(mut self, hr: &mut health_report::HealthReport) {
        if self.other_errors.is_empty() {
            passed(hr, probe_ids::BgpStats.clone(), None);
        } else {
            self.other_errors
                .insert(0, "Failures while gathering BGP health data:".to_string());
            let err_msg = self.other_errors.join("\n");
            failed(hr, probe_ids::BgpStats.clone(), None, err_msg);
        }

        let num_unhealthy_tors = self.unhealthy_tor_peers.len();
        // TODO: This is correct for environments with both DPU ports connected
        let unhealthy_tors_critical = num_unhealthy_tors > 1;
        for (port_name, message) in self.unhealthy_tor_peers.into_iter() {
            hr.alerts.push(make_alert(
                probe_ids::BgpPeeringTor.clone(),
                Some(port_name),
                message,
                unhealthy_tors_critical,
            ));
        }

        for (route_server, message) in self.unhealthy_route_server_peers.into_iter() {
            hr.alerts.push(make_alert(
                probe_ids::BgpPeeringRouteServer.clone(),
                Some(route_server.to_string()),
                message,
                true,
            ));
        }

        for (group, peer_name) in self.unexpected_peers.into_iter() {
            hr.alerts.push(make_alert(
                probe_ids::UnexpectedBgpPeer.clone(),
                Some(peer_name.clone()),
                format!("Unexpected BGP session referencing peer {peer_name} was found in {group}"),
                true,
            ));
        }
    }
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct BgpNetworks {
    ipv4_unicast: BgpStats,
    l2_vpn_evpn: BgpStats,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct BgpStats {
    dynamic_peers: u32,
    peers: HashMap<String, BgpPeer>,
}

impl BgpStats {
    /// Returns the list of peers that are not connected to TORs
    pub fn other_peers(&self) -> impl Iterator<Item = (&String, &BgpPeer)> {
        lazy_static::lazy_static! {
            static ref TOR_SESSION_RE: regex::Regex = regex::Regex::new(r"^p[0-9]+_[si]f$").unwrap();
        }

        self.peers
            .iter()
            .filter(|(name, _peer)| !TOR_SESSION_RE.is_match(name))
    }
}

// We don't currently check the two pfx values because they depend on how many correctly
// configured instances we have right now, and dpu-agent doesn't know that.
#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct BgpPeer {
    state: String,
    // pfx_rcd: Option<u32>, // unused
    // pfx_snt: Option<u32>, // unused
}

#[cfg(test)]
mod tests {
    use super::*;

    const BGP_SUMMARY_JSON_NO_ROUTE_SERVER_SUCCESS: &str =
        include_str!("../hbn_bgp_summary_no_route_server_success.json");
    const BGP_SUMMARY_JSON_NO_ROUTE_SERVER_FAILED_TOR_PEERS: &str =
        include_str!("../hbn_bgp_summary_no_route_server_failed_tor_peers.json");
    const BGP_SUMMARY_JSON_NO_ROUTE_SERVER_SINGLE_FAILED_TOR_PEER: &str =
        include_str!("../hbn_bgp_summary_no_route_server_single_failed_tor_peer.json");
    const BGP_SUMMARY_JSON_NO_ROUTE_SERVER_WITH_TENANT_ROUTES: &str =
        include_str!("../hbn_bgp_summary_no_route_server_with_tenant_routes.json");
    const BGP_SUMMARY_JSON_WITH_ROUTE_SERVER_AND_TENANT_ROUTES: &str =
        include_str!("../hbn_bgp_summary_with_route_server_and_tenant_routes.json");
    const BGP_SUMMARY_JSON_WITH_ROUTE_SERVER_FAILED_ALL_PEERS: &str =
        include_str!("../hbn_bgp_summary_with_route_server_failed_all_peers.json");

    #[test]
    fn test_check_bgp_success() -> eyre::Result<()> {
        let mut hr = health_report::HealthReport::empty("forge-dpu-agent".to_string());
        let mut health_data = BgpHealthData::default();
        verify_bgp_summary(
            &mut health_data,
            BGP_SUMMARY_JSON_NO_ROUTE_SERVER_SUCCESS,
            &[],
            2,
            &[],
            HBNDeviceNames::hbn_23(),
        );
        health_data.into_health_report(&mut hr);
        assert!(hr.alerts.is_empty());
        Ok(())
    }

    #[test]
    fn test_check_bgp_no_route_server_failed_tor_peers() -> eyre::Result<()> {
        let mut hr = health_report::HealthReport::empty("forge-dpu-agent".to_string());
        let mut health_data = BgpHealthData::default();
        verify_bgp_summary(
            &mut health_data,
            BGP_SUMMARY_JSON_NO_ROUTE_SERVER_FAILED_TOR_PEERS,
            &[],
            2,
            &[],
            HBNDeviceNames::hbn_23(),
        );
        health_data.into_health_report(&mut hr);
        assert_eq!(hr.alerts.len(), 2);
        hr.alerts
            .sort_by(|alert1, alert2| alert1.target.cmp(&alert2.target));

        assert_eq!(
            hr.alerts[0],
            make_alert(
                probe_ids::BgpPeeringTor.clone(),
                Some("p0_if".to_string()),
                "Session p0_if is not Established, but in state Idle".to_string(),
                true
            )
        );
        assert_eq!(
            hr.alerts[1],
            make_alert(
                probe_ids::BgpPeeringTor.clone(),
                Some("p1_if".to_string()),
                "Session p1_if is not Established, but in state Idle".to_string(),
                true
            )
        );
        Ok(())
    }

    #[test]
    fn test_check_bgp_no_route_server_single_failed_tor_peer() -> eyre::Result<()> {
        let mut hr = health_report::HealthReport::empty("forge-dpu-agent".to_string());
        let mut health_data = BgpHealthData::default();

        verify_bgp_summary(
            &mut health_data,
            BGP_SUMMARY_JSON_NO_ROUTE_SERVER_SINGLE_FAILED_TOR_PEER,
            &[],
            2,
            &[],
            HBNDeviceNames::hbn_23(),
        );
        health_data.into_health_report(&mut hr);
        assert_eq!(hr.alerts.len(), 1);
        hr.alerts
            .sort_by(|alert1, alert2| alert1.target.cmp(&alert2.target));

        assert_eq!(
            hr.alerts[0],
            make_alert(
                probe_ids::BgpPeeringTor.clone(),
                Some("p0_if".to_string()),
                "Session p0_if is not Established, but in state Idle".to_string(),
                false
            )
        );
        Ok(())
    }

    #[test]
    fn test_check_bgp_no_route_server_with_tenant_routes() -> eyre::Result<()> {
        let mut hr = health_report::HealthReport::empty("forge-dpu-agent".to_string());
        let mut health_data = BgpHealthData::default();
        verify_bgp_summary(
            &mut health_data,
            BGP_SUMMARY_JSON_NO_ROUTE_SERVER_WITH_TENANT_ROUTES,
            &["10.217.4.78"],
            2,
            &[],
            HBNDeviceNames::hbn_23(),
        );
        health_data.into_health_report(&mut hr);
        assert!(hr.alerts.is_empty());
        Ok(())
    }

    #[test]
    fn test_check_bgp_no_route_server_unexpected_tenant_route() -> eyre::Result<()> {
        let mut hr = health_report::HealthReport::empty("forge-dpu-agent".to_string());
        let mut health_data = BgpHealthData::default();
        verify_bgp_summary(
            &mut health_data,
            BGP_SUMMARY_JSON_NO_ROUTE_SERVER_WITH_TENANT_ROUTES,
            &[],
            2,
            &[],
            HBNDeviceNames::hbn_23(),
        );
        health_data.into_health_report(&mut hr);
        assert_eq!(hr.alerts.len(), 1);
        assert_eq!(
            hr.alerts[0],
            make_alert(
                probe_ids::UnexpectedBgpPeer.clone(),
                Some("10.217.4.78".to_string()),
                "Unexpected BGP session referencing peer 10.217.4.78 was found in ipv4_unicast"
                    .to_string(),
                true
            )
        );
        Ok(())
    }

    #[test]
    fn test_check_bgp_unexpected_route_server() -> eyre::Result<()> {
        let mut hr = health_report::HealthReport::empty("forge-dpu-agent".to_string());
        let mut health_data = BgpHealthData::default();
        verify_bgp_summary(
            &mut health_data,
            BGP_SUMMARY_JSON_WITH_ROUTE_SERVER_AND_TENANT_ROUTES,
            &["10.217.19.211"],
            2,
            &[],
            HBNDeviceNames::hbn_23(),
        );
        health_data.into_health_report(&mut hr);
        hr.alerts.sort_by(|alert1, alert2| {
            (&alert1.id, &alert1.target).cmp(&(&alert2.id, &alert2.target))
        });

        assert_eq!(
            hr.alerts[0],
            make_alert(
                probe_ids::BgpPeeringTor.clone(),
                Some("p0_if".to_string()),
                "Expected session for p0_if was not found in BGP peer data".to_string(),
                true
            )
        );
        assert_eq!(
            hr.alerts[1],
            make_alert(
                probe_ids::BgpPeeringTor.clone(),
                Some("p1_if".to_string()),
                "Expected session for p1_if was not found in BGP peer data".to_string(),
                true
            )
        );
        assert_eq!(
            hr.alerts[2],
            make_alert(
                probe_ids::UnexpectedBgpPeer.clone(),
                Some("10.217.126.67".to_string()),
                "Unexpected BGP session referencing peer 10.217.126.67 was found in l2_vpn_evpn"
                    .to_string(),
                true
            )
        );

        Ok(())
    }

    #[test]
    fn test_check_bgp_with_route_server_and_tenant_routes() -> eyre::Result<()> {
        let mut hr = health_report::HealthReport::empty("forge-dpu-agent".to_string());
        let mut health_data = BgpHealthData::default();
        verify_bgp_summary(
            &mut health_data,
            BGP_SUMMARY_JSON_WITH_ROUTE_SERVER_AND_TENANT_ROUTES,
            &["10.217.19.211"],
            2,
            &["10.217.126.67".to_string()],
            HBNDeviceNames::hbn_23(),
        );
        health_data.into_health_report(&mut hr);
        assert!(hr.alerts.is_empty());
        Ok(())
    }

    #[test]
    fn test_check_bgp_with_route_server_failed_all_peers() -> eyre::Result<()> {
        let mut hr = health_report::HealthReport::empty("forge-dpu-agent".to_string());
        let mut health_data = BgpHealthData::default();
        verify_bgp_summary(
            &mut health_data,
            BGP_SUMMARY_JSON_WITH_ROUTE_SERVER_FAILED_ALL_PEERS,
            &[],
            2,
            &["10.217.126.67".to_string()],
            HBNDeviceNames::hbn_23(),
        );
        health_data.into_health_report(&mut hr);
        assert_eq!(hr.alerts.len(), 3);
        hr.alerts
            .sort_by(|alert1, alert2| alert1.target.cmp(&alert2.target));

        assert_eq!(
            hr.alerts[0],
            make_alert(
                probe_ids::BgpPeeringRouteServer.clone(),
                Some("10.217.126.67".to_string()),
                "Session 10.217.126.67 is not Established, but in state Active".to_string(),
                true
            )
        );
        assert_eq!(
            hr.alerts[1],
            make_alert(
                probe_ids::BgpPeeringTor.clone(),
                Some("p0_if".to_string()),
                "Session p0_if is not Established, but in state Idle".to_string(),
                true
            )
        );
        assert_eq!(
            hr.alerts[2],
            make_alert(
                probe_ids::BgpPeeringTor.clone(),
                Some("p1_if".to_string()),
                "Session p1_if is not Established, but in state Idle".to_string(),
                true
            )
        );
        Ok(())
    }
}
