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

//! Tests for machine ID resolution in watcher events.

use std::sync::Arc;

use super::helpers::{Collector, WatcherMock, make_dpu, make_dpu_labeled};
use crate::crds::dpus_generated::*;
use crate::types::*;
use crate::watcher::DpuWatcherBuilder;

const TEST_NS: &str = "watcher-machine-id-ns";

#[tokio::test]
async fn test_machine_id_from_label() {
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
    m.emit_dpu(make_dpu_labeled(
        TEST_NS,
        "d1",
        "dev",
        "n1",
        DpuStatusPhase::Ready,
        "my-machine-id",
    ));
    c.wait_for(1).await;
    assert_eq!(c.get(0).unwrap().device_name, "dev");
}

#[tokio::test]
async fn test_machine_id_fallback() {
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
    m.emit_dpu(make_dpu(
        TEST_NS,
        "d1",
        "fallback-dev",
        "n1",
        DpuStatusPhase::Ready,
    ));
    c.wait_for(1).await;
    assert_eq!(c.get(0).unwrap().device_name, "fallback-dev");
}
