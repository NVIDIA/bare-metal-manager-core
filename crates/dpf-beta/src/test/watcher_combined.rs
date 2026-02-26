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

//! Tests for combined callback behavior and event filtering.

use std::sync::Arc;

use super::helpers::{Collector, WatcherMock, make_dpu, make_dpu_reboot};
use crate::crds::dpus_generated::*;
use crate::types::*;
use crate::watcher::DpuWatcherBuilder;

const TEST_NS: &str = "watcher-combined-ns";

#[tokio::test]
async fn test_ready_and_dpu_event_both_fire() {
    let m = Arc::new(WatcherMock::new());
    let dpu_events = Arc::new(Collector::<DpuEvent>::default());
    let ready = Arc::new(Collector::<DpuReadyEvent>::default());
    let dc = dpu_events.clone();
    let rc = ready.clone();
    let _h = DpuWatcherBuilder::new(m.clone(), TEST_NS)
        .on_dpu_event(move |e| {
            let dc = dc.clone();
            async move {
                dc.push(e);
                Ok(())
            }
        })
        .on_dpu_ready(move |e| {
            let rc = rc.clone();
            async move {
                rc.push(e);
                Ok(())
            }
        })
        .start();
    m.wait_for_watchers(1).await;
    m.emit_dpu(make_dpu(TEST_NS, "d1", "dev", "n1", DpuStatusPhase::Ready));
    dpu_events.wait_for(1).await;
    ready.wait_for(1).await;
    assert_eq!(dpu_events.get(0).unwrap().phase, DpuPhase::Ready);
    assert_eq!(ready.get(0).unwrap().dpu_name, "d1");
}

#[tokio::test]
async fn test_dpu_event_and_reboot_both_fire() {
    let m = Arc::new(WatcherMock::new());
    let dpu_events = Arc::new(Collector::<DpuEvent>::default());
    let reboot = Arc::new(Collector::<RebootRequiredEvent>::default());
    let dc = dpu_events.clone();
    let rc = reboot.clone();
    let _h = DpuWatcherBuilder::new(m.clone(), TEST_NS)
        .on_dpu_event(move |e| {
            let dc = dc.clone();
            async move {
                dc.push(e);
                Ok(())
            }
        })
        .on_reboot_required(move |e| {
            let rc = rc.clone();
            async move {
                rc.push(e);
                Ok(())
            }
        })
        .start();
    m.wait_for_watchers(1).await;
    m.emit_dpu(make_dpu_reboot(TEST_NS, "d1", "dev", "n1"));
    dpu_events.wait_for(1).await;
    reboot.wait_for(1).await;
    assert_eq!(dpu_events.get(0).unwrap().phase, DpuPhase::Rebooting);
    assert_eq!(reboot.get(0).unwrap().dpu_name, "d1");
}

#[tokio::test]
async fn test_dpu_no_status_ignored() {
    let m = Arc::new(WatcherMock::new());
    let c = Arc::new(Collector::<DpuEvent>::default());
    let cc = c.clone();
    let _h = DpuWatcherBuilder::new(m.clone(), TEST_NS)
        .on_dpu_event(move |e| {
            let cc = cc.clone();
            async move {
                cc.push(e);
                Ok(())
            }
        })
        .start();
    m.wait_for_watchers(1).await;
    let mut dpu_no_status = make_dpu(TEST_NS, "d1", "dev", "n1", DpuStatusPhase::Ready);
    dpu_no_status.status = None;
    m.emit_dpu(dpu_no_status);
    m.emit_dpu(make_dpu(
        TEST_NS,
        "sentinel",
        "dev",
        "n1",
        DpuStatusPhase::Ready,
    ));
    c.wait_for(1).await;
    assert_eq!(c.get(0).unwrap().dpu_name, "sentinel");
}

#[tokio::test]
async fn test_multiple_events() {
    let m = Arc::new(WatcherMock::new());
    let dpu_events = Arc::new(Collector::<DpuEvent>::default());
    let ready = Arc::new(Collector::<DpuReadyEvent>::default());
    let dc = dpu_events.clone();
    let rc = ready.clone();
    let _h = DpuWatcherBuilder::new(m.clone(), TEST_NS)
        .on_dpu_event(move |e| {
            let dc = dc.clone();
            async move {
                dc.push(e);
                Ok(())
            }
        })
        .on_dpu_ready(move |e| {
            let rc = rc.clone();
            async move {
                rc.push(e);
                Ok(())
            }
        })
        .start();
    m.wait_for_watchers(1).await;
    for i in 0..5 {
        let p = if i % 2 == 0 {
            DpuStatusPhase::Ready
        } else {
            DpuStatusPhase::Pending
        };
        m.emit_dpu(make_dpu(TEST_NS, &format!("d{}", i), "dev", "n1", p));
    }
    dpu_events.wait_for(5).await;
    ready.wait_for(3).await;
    assert_eq!(dpu_events.len(), 5);
    assert_eq!(ready.len(), 3);
}
