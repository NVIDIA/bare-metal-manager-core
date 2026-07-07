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

//! Guards the concurrency contract of `nv_generate_exploration_report`:
//!
//! 1. Independent Redfish fetches overlap (max in-flight >= 2), so a full
//!    exploration is bounded by the critical path instead of the sum of all
//!    round-trips.
//! 2. The fan-out never exceeds the per-BMC request cap (BMCs are fragile).
//! 3. Concurrency changes only the schedule, not the semantics: the same run
//!    against a transport-serialized mock (one request at a time) must issue
//!    the exact same request multiset and produce an identical report.
//! 4. `Config::max_concurrent_bmc_requests = 1` is the operator escape hatch
//!    for BMCs that dislike concurrent access: it must restore
//!    one-request-at-a-time behavior (max in-flight == 1) while still issuing
//!    the same request multiset and producing the same report.
//!
//! The mock BMC router is wrapped with an observing middleware that injects a
//! fixed per-request delay (so overlap is observable in wall-clock time) and
//! tracks in-flight/max-in-flight request counts plus the log of requested
//! paths.

mod common;

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::extract::{Request, State};
use axum::middleware::{self, Next};
use axum::response::Response;
use bmc_explorer::{DEFAULT_MAX_CONCURRENT_BMC_REQUESTS, nv_generate_exploration_report};
use bmc_mock::test_support::axum_http_client::AxumRouterHttpClient;
use bmc_mock::test_support::{NoopCallbacks, TEST_MAC_POOL, TestBmc};
use bmc_mock::{
    DpuMachineInfo, DpuSettings, HostHardwareType, HostMachineInfo, MachineInfo, machine_router,
};
use model::site_explorer::EndpointExplorationReport;
use nv_redfish::bmc_http::{BmcCredentials, CacheSettings, HttpBmc};
use tokio::test;
use url::Url;

/// Injected latency for every mock BMC request. Large enough that overlapping
/// requests dominate the wall clock, small enough to keep the test fast.
const PER_REQUEST_DELAY: Duration = Duration::from_millis(25);

/// Tracks the concurrency profile of requests flowing through the mock BMC.
#[derive(Clone, Default)]
struct RequestObserver {
    in_flight: Arc<AtomicUsize>,
    max_in_flight: Arc<AtomicUsize>,
    paths: Arc<Mutex<Vec<String>>>,
}

impl RequestObserver {
    /// Clears counters, so measurement covers only the exploration itself
    /// (not the `ServiceRoot` bootstrap).
    fn reset(&self) {
        self.in_flight.store(0, Ordering::SeqCst);
        self.max_in_flight.store(0, Ordering::SeqCst);
        self.paths.lock().unwrap().clear();
    }

    fn max_in_flight(&self) -> usize {
        self.max_in_flight.load(Ordering::SeqCst)
    }

    fn request_count(&self) -> usize {
        self.paths.lock().unwrap().len()
    }

    /// The requested paths as a multiset (path -> occurrence count).
    fn multiset(&self) -> BTreeMap<String, usize> {
        let mut multiset = BTreeMap::new();
        for path in self.paths.lock().unwrap().iter() {
            *multiset.entry(path.clone()).or_insert(0) += 1;
        }
        multiset
    }
}

/// Middleware: records the requested path, tracks in-flight/max-in-flight, and
/// injects [`PER_REQUEST_DELAY`] while the request counts as in-flight.
async fn observe(
    State(observer): State<RequestObserver>,
    request: Request,
    next: Next,
) -> Response {
    observer
        .paths
        .lock()
        .unwrap()
        .push(request.uri().path().to_string());
    let now_in_flight = observer.in_flight.fetch_add(1, Ordering::SeqCst) + 1;
    observer
        .max_in_flight
        .fetch_max(now_in_flight, Ordering::SeqCst);
    tokio::time::sleep(PER_REQUEST_DELAY).await;
    let response = next.run(request).await;
    observer.in_flight.fetch_sub(1, Ordering::SeqCst);
    response
}

/// Middleware: admits one request at a time. Wrapping the observer with this
/// gate yields the serial reference run: the same exploration code, forced to
/// execute its requests sequentially at the transport.
async fn serialize_requests(
    State(gate): State<Arc<tokio::sync::Semaphore>>,
    request: Request,
    next: Next,
) -> Response {
    let _permit = gate
        .acquire()
        .await
        .expect("serialization gate is never closed");
    next.run(request).await
}

struct InstrumentedBmc {
    service_root: Arc<nv_redfish::ServiceRoot<TestBmc>>,
    observer: RequestObserver,
}

async fn instrumented_bmc(
    machine_info: &MachineInfo,
    machine_id: &str,
    serialized: bool,
) -> InstrumentedBmc {
    let (router, _state) = machine_router(
        machine_info,
        Arc::new(NoopCallbacks),
        machine_id.to_string(),
        false,
    );
    let observer = RequestObserver::default();
    let mut router = router.layer(middleware::from_fn_with_state(observer.clone(), observe));
    if serialized {
        // Applied after (thus outside of) the observer, so the gate is held
        // across the observer's whole span: a serialized run must report
        // max_in_flight == 1, which doubles as proof the observer works.
        router = router.layer(middleware::from_fn_with_state(
            Arc::new(tokio::sync::Semaphore::new(1)),
            serialize_requests,
        ));
    }

    let client = AxumRouterHttpClient::new(router);
    let endpoint = Url::parse("https://bmc-mock.local").expect("valid URL");
    let credentials = BmcCredentials::new("root".to_string(), "password".to_string());
    let bmc = Arc::new(HttpBmc::new(
        client,
        endpoint,
        credentials,
        CacheSettings::with_capacity(32),
    ));
    let service_root = nv_redfish::ServiceRoot::new(bmc)
        .await
        .expect("service root")
        .into();
    // Measure the exploration only, not the ServiceRoot bootstrap.
    observer.reset();
    InstrumentedBmc {
        service_root,
        observer,
    }
}

struct Measurement {
    report: EndpointExplorationReport,
    wall_clock: Duration,
    max_in_flight: usize,
    request_count: usize,
    multiset: BTreeMap<String, usize>,
}

/// Compile-time guard: the exploration future must stay `Send` for a `Send`
/// transport — site-explorer awaits it from spawned (Send-checked) tasks.
/// Stream adapters whose closures take borrowed items embed closure types in
/// the future and break this proof (rustc "implementation of `FnOnce`/`Send`
/// is not general enough"), so a regression fails compilation right here.
fn require_send<T: Send>(value: T) -> T {
    value
}

async fn measure(
    machine_info: &MachineInfo,
    machine_id: &str,
    serialized: bool,
    max_concurrent_bmc_requests: usize,
) -> Measurement {
    let bmc = instrumented_bmc(machine_info, machine_id, serialized).await;
    let config = bmc_explorer::Config {
        max_concurrent_bmc_requests,
        ..common::explorer_config()
    };
    let started = Instant::now();
    let report = require_send(nv_generate_exploration_report(bmc.service_root, &config))
        .await
        .expect("exploration must succeed");
    let wall_clock = started.elapsed();
    Measurement {
        report,
        wall_clock,
        max_in_flight: bmc.observer.max_in_flight(),
        request_count: bmc.observer.request_count(),
        multiset: bmc.observer.multiset(),
    }
}

fn print_measurements(
    label: &str,
    serialized: &Measurement,
    free: &Measurement,
    capped_to_one: &Measurement,
) {
    println!(
        "[measure:{label}] serialized: wall_clock={:?} requests={} max_in_flight={}",
        serialized.wall_clock, serialized.request_count, serialized.max_in_flight,
    );
    println!(
        "[measure:{label}] free:       wall_clock={:?} requests={} max_in_flight={}",
        free.wall_clock, free.request_count, free.max_in_flight,
    );
    println!(
        "[measure:{label}] cap=1:      wall_clock={:?} requests={} max_in_flight={}",
        capped_to_one.wall_clock, capped_to_one.request_count, capped_to_one.max_in_flight,
    );
    println!(
        "[measure:{label}] request multiset ({} paths): {:?}",
        free.request_count, free.multiset,
    );
}

fn assert_concurrent_run_matches_serial_reference(
    label: &str,
    serialized: &Measurement,
    free: &Measurement,
    capped_to_one: &Measurement,
) {
    print_measurements(label, serialized, free, capped_to_one);

    // The gated run proves the observer detects serial execution: exactly one
    // request may be in flight.
    assert_eq!(
        serialized.max_in_flight, 1,
        "transport-serialized run must never overlap requests",
    );
    assert!(
        serialized.request_count > 0,
        "observer must have seen the exploration requests",
    );

    // Deterministic concurrency proof: independent fetches must overlap.
    assert!(
        free.max_in_flight >= 2,
        "exploration must overlap independent requests, max_in_flight={}",
        free.max_in_flight,
    );
    // ... but never beyond the per-BMC cap.
    assert!(
        free.max_in_flight <= DEFAULT_MAX_CONCURRENT_BMC_REQUESTS,
        "exploration must respect the default per-BMC request cap of \
         {DEFAULT_MAX_CONCURRENT_BMC_REQUESTS}, max_in_flight={}",
        free.max_in_flight,
    );

    // Semantic parity: concurrency changes the schedule, not the requests
    // issued nor the report produced.
    assert_eq!(
        serialized.multiset, free.multiset,
        "concurrent exploration must issue exactly the requests of a serial run",
    );
    assert_eq!(
        serialized.report, free.report,
        "concurrent exploration must produce the identical report",
    );

    // The operator escape hatch: a cap of 1 must restore one-request-at-a-time
    // behavior at the client (for BMCs that dislike concurrent access), while
    // still issuing the same requests and producing the same report.
    assert_eq!(
        capped_to_one.max_in_flight, 1,
        "cap=1 exploration must never overlap requests",
    );
    assert_eq!(
        capped_to_one.multiset, free.multiset,
        "cap=1 exploration must issue exactly the requests of the free run",
    );
    assert_eq!(
        capped_to_one.report, free.report,
        "cap=1 exploration must produce the identical report",
    );

    // Wall clocks are diagnostic output only: the deterministic guards above
    // (max-in-flight, request multiset, report equality) prove the overlap,
    // and any timing comparison could flake on a loaded runner.
    println!(
        "wall clocks -- serialized: {:?}, free: {:?}, cap=1: {:?}",
        serialized.wall_clock, free.wall_clock, capped_to_one.wall_clock,
    );
}

fn dell_r750_host_info() -> MachineInfo {
    let hw_type = HostHardwareType::DellPowerEdgeR750;
    let mut pool = TEST_MAC_POOL.lock().unwrap();
    let ranges_config = pool.allocate_range_config().expect("range config");
    let dpu_count = hw_type.fixed_number_of_dpu().unwrap_or(0);
    MachineInfo::Host(HostMachineInfo::new(
        hw_type,
        (0..dpu_count)
            .map(|_| DpuMachineInfo::new(hw_type, &mut pool, DpuSettings::default()))
            .collect(),
        &mut pool,
        ranges_config,
    ))
}

fn bluefield3_dpu_info() -> MachineInfo {
    let mut pool = TEST_MAC_POOL.lock().unwrap();
    MachineInfo::Dpu(DpuMachineInfo::new(
        HostHardwareType::DellPowerEdgeR750,
        &mut pool,
        DpuSettings::default(),
    ))
}

/// Dell host BMC: exercises the network-device-function fan-out (Dell explores
/// adapters with `need_network_device_fns`) and the Dell manager OEM branch.
#[test]
async fn exploration_overlaps_requests_with_parity_dell_r750() {
    let machine_info = dell_r750_host_info();
    let serialized = measure(
        &machine_info,
        "test-host-id",
        true,
        DEFAULT_MAX_CONCURRENT_BMC_REQUESTS,
    )
    .await;
    let free = measure(
        &machine_info,
        "test-host-id",
        false,
        DEFAULT_MAX_CONCURRENT_BMC_REQUESTS,
    )
    .await;
    let capped_to_one = measure(&machine_info, "test-host-id", false, 1).await;
    assert_concurrent_run_matches_serial_reference("dell_r750", &serialized, &free, &capped_to_one);
}

/// BlueField-3 DPU BMC: exercises the lazily-fetched chassis links (with the
/// ERoT skip filter) and the BlueField computer-system branches (OEM +
/// secure-boot + eth-interface retry path).
#[test]
async fn exploration_overlaps_requests_with_parity_bluefield3_dpu() {
    let machine_info = bluefield3_dpu_info();
    let serialized = measure(
        &machine_info,
        "test-dpu-id",
        true,
        DEFAULT_MAX_CONCURRENT_BMC_REQUESTS,
    )
    .await;
    let free = measure(
        &machine_info,
        "test-dpu-id",
        false,
        DEFAULT_MAX_CONCURRENT_BMC_REQUESTS,
    )
    .await;
    let capped_to_one = measure(&machine_info, "test-dpu-id", false, 1).await;
    assert_concurrent_run_matches_serial_reference(
        "bluefield3_dpu",
        &serialized,
        &free,
        &capped_to_one,
    );
}
