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

//! Tests for the on_reboot_required callback.

use std::sync::Arc;

use super::helpers::{Collector, WatcherMock, make_dpu, make_dpu_reboot};
use crate::crds::dpus_generated::*;
use crate::types::*;
use crate::watcher::DpuWatcherBuilder;

const TEST_NS: &str = "watcher-reboot-ns";

#[tokio::test]
async fn test_reboot_invoked() {
    let m = Arc::new(WatcherMock::new());
    let c = Arc::new(Collector::<RebootRequiredEvent>::default());
    let cc = c.clone();
    let _h = DpuWatcherBuilder::new(m.clone(), TEST_NS)
        .on_reboot_required(move |e| {
            let cc = cc.clone();
            async move {
                cc.push(e);
                Ok(())
            }
        })
        .start();
    m.wait_for_watchers(1).await;
    m.emit_dpu(make_dpu_reboot(TEST_NS, "d1", "dev", "n1"));
    c.wait_for(1).await;
    assert_eq!(c.get(0).unwrap().dpu_name, "d1");
}

#[tokio::test]
async fn test_reboot_not_invoked_no_flag() {
    let m = Arc::new(WatcherMock::new());
    let reboot = Arc::new(Collector::<RebootRequiredEvent>::default());
    let dpu_events = Arc::new(Collector::<DpuEvent>::default());
    let rc = reboot.clone();
    let dc = dpu_events.clone();
    let _h = DpuWatcherBuilder::new(m.clone(), TEST_NS)
        .on_reboot_required(move |e| {
            let rc = rc.clone();
            async move {
                rc.push(e);
                Ok(())
            }
        })
        .on_dpu_event(move |e| {
            let dc = dc.clone();
            async move {
                dc.push(e);
                Ok(())
            }
        })
        .start();
    m.wait_for_watchers(1).await;
    m.emit_dpu(make_dpu(TEST_NS, "d1", "dev", "n1", DpuStatusPhase::Ready));
    dpu_events.wait_for(1).await;
    assert_eq!(reboot.len(), 0);
}

#[tokio::test]
async fn test_reboot_bmc_ip() {
    let m = Arc::new(WatcherMock::new());
    let c = Arc::new(Collector::<RebootRequiredEvent>::default());
    let cc = c.clone();
    let _h = DpuWatcherBuilder::new(m.clone(), TEST_NS)
        .on_reboot_required(move |e| {
            let cc = cc.clone();
            async move {
                cc.push(e);
                Ok(())
            }
        })
        .start();
    m.wait_for_watchers(1).await;
    let mut dpu = make_dpu_reboot(TEST_NS, "d1", "dev", "n1");
    dpu.spec.bmc_ip = Some("10.0.0.42".into());
    m.emit_dpu(dpu);
    c.wait_for(1).await;
    assert_eq!(c.get(0).unwrap().host_bmc_ip, "10.0.0.42");
}
