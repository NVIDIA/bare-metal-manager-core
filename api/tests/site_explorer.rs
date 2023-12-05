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
    collections::HashMap,
    net::IpAddr,
    sync::{Arc, Mutex},
};

use carbide::{
    cfg::SiteExplorerConfig,
    db::{explored_endpoints::ExploredEndpoint, machine_interface::MachineInterface},
    model::site_explorer::{EndpointExplorationError, EndpointExplorationReport, EndpointType},
    site_explorer::{EndpointExplorer, SiteExplorer},
    state_controller::network_segment::handler::NetworkSegmentStateHandler,
};
use rpc::forge::{forge_server::Forge, DhcpDiscovery};

mod common;
use common::{api_fixtures::TestEnv, network_segment::FIXTURE_CREATED_DOMAIN_UUID};

#[ctor::ctor]
fn setup() {
    common::test_logging::init();
}

async fn create_network_segment(
    env: &TestEnv,
    name: &str,
    prefix: &str,
    gateway: &str,
    segment_type: rpc::forge::NetworkSegmentType,
) -> uuid::Uuid {
    let request = rpc::forge::NetworkSegmentCreationRequest {
        mtu: Some(1500),
        name: name.to_string(),
        prefixes: vec![rpc::forge::NetworkPrefix {
            id: None,
            prefix: prefix.to_string(),
            gateway: Some(gateway.to_string()),
            reserve_first: 1,
            state: None,
            events: vec![],
            circuit_id: None,
        }],
        subdomain_id: Some(FIXTURE_CREATED_DOMAIN_UUID.into()),
        vpc_id: None,
        segment_type: segment_type as _,
    };

    let response = env
        .api
        .create_network_segment(tonic::Request::new(request))
        .await
        .expect("Unable to create network segment")
        .into_inner();
    let segment_id: uuid::Uuid = response.id.unwrap().try_into().unwrap();

    // Get the segment into ready state
    let handler = NetworkSegmentStateHandler::new(
        chrono::Duration::milliseconds(500),
        env.common_pools.ethernet.pool_vlan_id.clone(),
        env.common_pools.ethernet.pool_vni.clone(),
    );
    env.run_network_segment_controller_iteration(segment_id, &handler)
        .await;
    env.run_network_segment_controller_iteration(segment_id, &handler)
        .await;

    segment_id
}

async fn create_underlay_network_segment(env: &TestEnv) -> uuid::Uuid {
    create_network_segment(
        env,
        "UNDERLAY",
        "192.0.1.0/24",
        "192.0.1.1",
        rpc::forge::NetworkSegmentType::Underlay,
    )
    .await
}

async fn create_admin_network_segment(env: &TestEnv) -> uuid::Uuid {
    create_network_segment(
        env,
        "ADMIN",
        "192.0.2.0/24",
        "192.0.2.1",
        rpc::forge::NetworkSegmentType::Admin,
    )
    .await
}

struct FakeMachine {
    pub mac: String,
    pub dhcp_vendor: String,
    pub segment: uuid::Uuid,
    pub ip: String,
}

#[sqlx::test(fixtures("create_domain", "create_vpc"))]
async fn test_site_explorer(pool: sqlx::PgPool) -> Result<(), Box<dyn std::error::Error>> {
    let env = common::api_fixtures::create_test_env(pool.clone()).await;

    let underlay_segment = create_underlay_network_segment(&env).await;
    let admin_segment = create_admin_network_segment(&env).await;

    // Let's create 3 machines on the underlay, and 1 on the admin network
    // The 1 on the admin network is not supposed to be searched. This is verified
    // by providing no mocked exploration data for this machine, which would lead
    // to a panic if the machine is queried
    let mut machines = vec![
        FakeMachine {
            mac: "AA:AB:AC:AD:AA:01".to_string(),
            dhcp_vendor: "Vendor1".to_string(),
            segment: underlay_segment,
            ip: String::new(),
        },
        FakeMachine {
            mac: "AA:AB:AC:AD:AA:02".to_string(),
            dhcp_vendor: "Vendor2".to_string(),
            segment: underlay_segment,
            ip: String::new(),
        },
        FakeMachine {
            mac: "AA:AB:AC:AD:AA:03".to_string(),
            dhcp_vendor: "Vendor3".to_string(),
            segment: underlay_segment,
            ip: String::new(),
        },
        FakeMachine {
            mac: "AA:AB:AC:AD:BB:001".to_string(),
            dhcp_vendor: "VendorInvalidSegment".to_string(),
            segment: admin_segment,
            ip: String::new(),
        },
    ];

    for machine in &mut machines {
        let response = env
            .api
            .discover_dhcp(tonic::Request::new(DhcpDiscovery {
                mac_address: machine.mac.clone(),
                relay_address: match machine.segment {
                    s if s == underlay_segment => "192.0.1.1".to_string(),
                    _ => "192.0.2.1".to_string(),
                },
                link_address: None,
                vendor_string: Some(machine.dhcp_vendor.clone()),
                circuit_id: None,
                remote_id: None,
            }))
            .await
            .unwrap()
            .into_inner();
        tracing::info!(
            "DHCP with mac {} assigned ip {}",
            machine.mac,
            response.address
        );
        machine.ip = response.address;
    }

    let mut txn = pool.begin().await?;
    assert_eq!(
        MachineInterface::count_by_segment_id(&mut txn, &underlay_segment)
            .await
            .unwrap(),
        3
    );
    assert_eq!(
        MachineInterface::count_by_segment_id(&mut txn, &admin_segment)
            .await
            .unwrap(),
        1
    );
    txn.commit().await.unwrap();

    let explorer_config = SiteExplorerConfig {
        enabled: true,
        explorations_per_run: 2,
        concurrent_explorations: 1,
        run_interval: 1,
    };
    let endpoint_explorer = Arc::new(FakeEndpointExplorer {
        reports: Arc::new(Mutex::new(HashMap::new())),
    });

    {
        let mut guard = endpoint_explorer.reports.lock().unwrap();
        guard.insert(
            machines[0].ip.parse().unwrap(),
            Ok(EndpointExplorationReport {
                endpoint_type: EndpointType::Bmc,
                last_exploration_error: None,
                vendor: Some("NVIDIA".to_string()),
                managers: Vec::new(),
                systems: Vec::new(),
            }),
        );
        guard.insert(
            machines[1].ip.parse().unwrap(),
            Err(EndpointExplorationError::Unauthorized {
                details: "Not authorized".to_string(),
            }),
        );
        guard.insert(
            machines[2].ip.parse().unwrap(),
            Ok(EndpointExplorationReport {
                endpoint_type: EndpointType::Bmc,
                last_exploration_error: None,
                vendor: Some("Vendor3".to_string()),
                managers: Vec::new(),
                systems: Vec::new(),
            }),
        );
    }

    let meter = opentelemetry::global::meter("test");
    let explorer = SiteExplorer::new(
        pool.clone(),
        Some(&explorer_config),
        meter,
        endpoint_explorer.clone(),
    );

    explorer.run_single_iteration().await.unwrap();
    // Since we configured a limit of 2 entries, we should have those 2 results now
    let mut txn = pool.begin().await?;
    let explored = ExploredEndpoint::find_all(&mut txn).await.unwrap();
    txn.commit().await?;
    assert_eq!(explored.len(), 2);

    for report in &explored {
        assert_eq!(report.exploration_report.version.version_nr(), 1);
        let guard = endpoint_explorer.reports.lock().unwrap();
        let res = guard.get(&report.address).unwrap();
        if res.is_err() {
            assert_eq!(
                res.clone().unwrap_err(),
                report
                    .exploration_report
                    .last_exploration_error
                    .clone()
                    .unwrap()
            );
        } else {
            assert_eq!(res.clone().unwrap(), report.exploration_report.value);
        }
    }

    // Running again should yield all 3 entries
    explorer.run_single_iteration().await.unwrap();
    // Since we configured a limit of 2 entries, we should have those 2 results now
    let mut txn = pool.begin().await?;
    let explored = ExploredEndpoint::find_all(&mut txn).await.unwrap();
    txn.commit().await?;
    assert_eq!(explored.len(), 3);
    let mut versions = Vec::new();
    for report in &explored {
        versions.push(report.exploration_report.version.version_nr());
        let guard = endpoint_explorer.reports.lock().unwrap();
        let res = guard.get(&report.address).unwrap();
        if res.is_err() {
            assert_eq!(
                res.clone().unwrap_err(),
                report
                    .exploration_report
                    .last_exploration_error
                    .clone()
                    .unwrap()
            );
        } else {
            assert_eq!(res.clone().unwrap(), report.exploration_report.value);
        }
    }
    versions.sort();
    assert_eq!(&versions, &[1, 1, 2]);

    // Now make 1 previously existing endpoint unreachable and 1 previously unreachable
    // endpoint reachable.
    // Both changes should show up after 2 updates
    {
        let mut guard = endpoint_explorer.reports.lock().unwrap();
        let m0 = guard.get_mut(&machines[0].ip.parse().unwrap()).unwrap();
        *m0 = Err(EndpointExplorationError::Unreachable);

        let m1 = guard.get_mut(&machines[1].ip.parse().unwrap()).unwrap();
        *m1 = Ok(EndpointExplorationReport {
            endpoint_type: EndpointType::Bmc,
            last_exploration_error: None,
            vendor: Some("Vendor2".to_string()),
            managers: Vec::new(),
            systems: Vec::new(),
        });
    }

    explorer.run_single_iteration().await.unwrap();
    explorer.run_single_iteration().await.unwrap();
    let mut txn = pool.begin().await?;
    let explored = ExploredEndpoint::find_all(&mut txn).await.unwrap();
    txn.commit().await?;
    assert_eq!(explored.len(), 3);
    let mut versions = Vec::new();
    for report in &explored {
        versions.push(report.exploration_report.version.version_nr());
        assert_eq!(report.exploration_report.endpoint_type, EndpointType::Bmc);
        match report.address.to_string() {
            a if a == machines[0].ip => {
                // The original report is retained. But the error gets stored
                assert_eq!(report.exploration_report.vendor, Some("NVIDIA".to_string()));
                assert_eq!(
                    report
                        .exploration_report
                        .last_exploration_error
                        .clone()
                        .unwrap(),
                    EndpointExplorationError::Unreachable
                );
            }
            a if a == machines[1].ip => {
                assert_eq!(
                    report.exploration_report.vendor,
                    Some("Vendor2".to_string())
                );
                assert!(report.exploration_report.last_exploration_error.is_none());
            }
            a if a == machines[2].ip => {
                assert_eq!(
                    report.exploration_report.vendor,
                    Some("Vendor3".to_string())
                );
                assert!(report.exploration_report.last_exploration_error.is_none());
            }
            _ => panic!("No other endpoints should be discovered"),
        }
    }
    versions.sort();
    // We run 4 iterations, which is enough for 8 machine scans
    // => 2 Machines should have been scanned 3 times, and one 2 times
    assert_eq!(&versions, &[2, 3, 3]);

    Ok(())
}

/// EndpointExplorer which returns predefined data
struct FakeEndpointExplorer {
    reports:
        Arc<Mutex<HashMap<IpAddr, Result<EndpointExplorationReport, EndpointExplorationError>>>>,
}

#[async_trait::async_trait]
impl EndpointExplorer for FakeEndpointExplorer {
    async fn explore_endpoint(
        &self,
        address: &IpAddr,
        _interface: &MachineInterface,
        _last_report: Option<&EndpointExplorationReport>,
    ) -> Result<EndpointExplorationReport, EndpointExplorationError> {
        tracing::info!("Endpoint {address} is getting explored");
        let guard = self.reports.lock().unwrap();
        let res = guard.get(address).unwrap();
        res.clone()
    }
}
