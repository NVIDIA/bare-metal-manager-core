/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */

//! Tests for the on_error callback.

use std::sync::Arc;

use super::helpers::{Collector, WatcherMock, make_dpu};
use crate::crds::dpus_generated::*;
use crate::types::*;
use crate::watcher::DpuWatcherBuilder;

const TEST_NS: &str = "watcher-error-ns";

#[tokio::test]
async fn test_error_fires_on_error_phase() {
    let m = Arc::new(WatcherMock::new());
    let c = Arc::new(Collector::<DpuErrorEvent>::default());
    let cc = c.clone();
    let _h = DpuWatcherBuilder::new(m.clone(), TEST_NS)
        .on_error(move |e| {
            let cc = cc.clone();
            async move {
                cc.push(e);
                Ok(())
            }
        })
        .start();
    m.wait_for_watchers(1).await;
    m.emit_dpu(make_dpu(TEST_NS, "d1", "dev1", "n1", DpuStatusPhase::Error));
    c.wait_for(1).await;
    assert_eq!(c.get(0).unwrap().dpu_name, "d1");
    assert_eq!(c.get(0).unwrap().device_name, "dev1");
    assert_eq!(c.get(0).unwrap().node_name, "n1");
}

#[tokio::test]
async fn test_error_does_not_fire_on_ready() {
    let m = Arc::new(WatcherMock::new());
    let error_events = Arc::new(Collector::<DpuErrorEvent>::default());
    let dpu_events = Arc::new(Collector::<DpuEvent>::default());

    let ec = error_events.clone();
    let dc = dpu_events.clone();
    let _h = DpuWatcherBuilder::new(m.clone(), TEST_NS)
        .on_dpu_event(move |e| {
            let dc = dc.clone();
            async move {
                dc.push(e);
                Ok(())
            }
        })
        .on_error(move |e| {
            let ec = ec.clone();
            async move {
                ec.push(e);
                Ok(())
            }
        })
        .start();
    m.wait_for_watchers(1).await;
    m.emit_dpu(make_dpu(TEST_NS, "d1", "dev1", "n1", DpuStatusPhase::Ready));
    dpu_events.wait_for(1).await;
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    assert_eq!(error_events.len(), 0, "on_error should not fire on Ready");
}

#[tokio::test]
async fn test_error_and_dpu_event_both_fire() {
    let m = Arc::new(WatcherMock::new());
    let error_events = Arc::new(Collector::<DpuErrorEvent>::default());
    let dpu_events = Arc::new(Collector::<DpuEvent>::default());

    let ec = error_events.clone();
    let dc = dpu_events.clone();
    let _h = DpuWatcherBuilder::new(m.clone(), TEST_NS)
        .on_dpu_event(move |e| {
            let dc = dc.clone();
            async move {
                dc.push(e);
                Ok(())
            }
        })
        .on_error(move |e| {
            let ec = ec.clone();
            async move {
                ec.push(e);
                Ok(())
            }
        })
        .start();
    m.wait_for_watchers(1).await;
    m.emit_dpu(make_dpu(TEST_NS, "d1", "dev1", "n1", DpuStatusPhase::Error));
    dpu_events.wait_for(1).await;
    error_events.wait_for(1).await;
    assert_eq!(dpu_events.get(0).unwrap().phase, DpuPhase::Error);
    assert_eq!(error_events.get(0).unwrap().dpu_name, "d1");
}
