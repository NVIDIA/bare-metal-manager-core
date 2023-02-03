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

//! Contains host related fixtures

use carbide::model::hardware_info::HardwareInfo;

const TEST_DATA_DIR: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/src/model/hardware_info/test_data"
);

/// Creates a `HardwareInfo` object which represents a DPU
pub fn create_host_hardware_info() -> HardwareInfo {
    let path = format!("{}/x86_info.json", TEST_DATA_DIR);
    let data = std::fs::read(path).unwrap();
    let info = serde_json::from_slice::<HardwareInfo>(&data).unwrap();
    assert!(!info.is_dpu());
    info
}
