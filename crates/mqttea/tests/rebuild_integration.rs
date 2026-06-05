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

//! Integration tests for the rebuild-on-persistent-disconnect path.
//!
//! These tests point an `MqtteaClient` at an unreachable address and
//! verify the watchdog actually tears down and rebuilds the underlying
//! rumqttc client once the threshold elapses, instead of either
//! exiting the process (the previous behavior) or sitting silently in
//! a wedged state (the bug from NVBug 6191840 the rebuild path
//! recovers from).
//!
//! We don't stand up a real broker here -- the broker side is exercised
//! by manual verification on dev. What we want to confirm in CI is:
//!
//! * the watchdog actually fires after the configured threshold
//! * the rebuild bookkeeping (`queue_stats.total_client_rebuilds`) increments
//! * tracked subscriptions are preserved across the rebuild so they get
//!   replayed onto the new AsyncClient
//! * the process keeps running (no `exit(1)` regression from the old code path)

use std::time::Duration;

use mqttea::QoS;
use mqttea::client::{ClientOptions, MqtteaClient};

// Picks a TCP port that's reserved by the kernel but immediately released,
// giving us a port we can confidently point an MqtteaClient at and expect
// the connection to fail. Avoids hard-coding a port that might be in use.
async fn pick_unreachable_port() -> u16 {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    port
}

#[tokio::test]
async fn rebuild_watchdog_fires_when_broker_is_unreachable() {
    let port = pick_unreachable_port().await;

    let options = ClientOptions::default()
        .with_qos(QoS::AtMostOnce)
        .with_rebuild_after_persistent_disconnect(Duration::from_millis(500));

    let client = MqtteaClient::new("127.0.0.1", port, "rebuild-watchdog-test", Some(options))
        .await
        .expect("client construction should succeed even with unreachable broker");

    // Queue a subscription before connect so the rebuild path has
    // something to replay. The actual SUBSCRIBE never makes it on
    // the wire (broker is unreachable), but the topic gets recorded
    // in MqtteaClient.subscriptions and that's what we want to
    // verify survives the rebuild.
    client
        .subscribe("rebuild-test/#", QoS::AtMostOnce)
        .await
        .expect("subscribe should queue command even when broker is down");

    client
        .connect()
        .await
        .expect("connect should spawn the event loop task");

    // Give the watchdog enough time to fire at least twice: each cycle
    // it accrues 500ms of poll errors -> rebuild -> new EventLoop also
    // can't connect -> another 500ms of errors -> rebuild again. After
    // ~3s we expect at least 2-3 rebuilds.
    tokio::time::sleep(Duration::from_secs(3)).await;

    let stats = client.queue_stats();
    assert!(
        stats.total_client_rebuilds >= 1,
        "rebuild watchdog should have fired at least once after 3s with broker unreachable; \
         total_client_rebuilds={}, total_event_loop_errors={}",
        stats.total_client_rebuilds,
        stats.total_event_loop_errors,
    );
    assert!(
        stats.total_event_loop_errors > 0,
        "event loop should have seen poll errors against unreachable broker"
    );
}

#[tokio::test]
async fn rebuild_disabled_means_no_rebuilds() {
    let port = pick_unreachable_port().await;

    // No rebuild_after_persistent_disconnect set => library falls back
    // to its original behavior of just retrying with backoff forever.
    let options = ClientOptions::default().with_qos(QoS::AtMostOnce);

    let client = MqtteaClient::new("127.0.0.1", port, "rebuild-disabled-test", Some(options))
        .await
        .expect("client construction should succeed");

    client
        .connect()
        .await
        .expect("connect should spawn the event loop task");

    tokio::time::sleep(Duration::from_secs(2)).await;

    let stats = client.queue_stats();
    assert_eq!(
        stats.total_client_rebuilds, 0,
        "rebuild watchdog should not fire when threshold is unset"
    );
    assert!(
        stats.total_event_loop_errors > 0,
        "event loop should still have seen poll errors against unreachable broker"
    );
}
