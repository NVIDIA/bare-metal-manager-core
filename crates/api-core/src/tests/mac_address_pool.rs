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

// Tests for test_support/mac_address_pool.rs
// They can't be in the support file because otherwise every test crate would also run those tests.

use mac_address::MacAddress;

use crate::test_support::mac_address_pool::{
    DPU_BMC_MAC_ADDRESS_POOL_CONFIG, DPU_OOB_MAC_ADDRESS_POOL_CONFIG,
    EXPECTED_POWER_SHELF_BMC_MAC_ADDRESS_POOL_CONFIG, EXPECTED_SWITCH_BMC_MAC_ADDRESS_POOL_CONFIG,
    EXPECTED_SWITCH_NVOS_MAC_ADDRESS_POOL_CONFIG, HOST_BMC_MAC_ADDRESS_POOL_CONFIG,
    HOST_MAC_ADDRESS_POOL_CONFIG, HOST_NON_DPU_MAC_ADDRESS_POOL_CONFIG, MacAddressPool,
    MacAddressPoolConfig,
};

#[test]
fn allocate_addresses() {
    let pool = MacAddressPool::new(MacAddressPoolConfig {
        start: [0x11, 0x12, 0x13, 0x14, 0x15, 0x1],
        length: 256,
    });
    assert!(!pool.contains(MacAddress::new([0x11, 0x12, 0x13, 0x14, 0x15, 0])));

    for i in 1..=255 {
        let expected = MacAddress::new([0x11, 0x12, 0x13, 0x14, 0x15, i as u8]);
        assert_eq!(pool.allocate(), expected);
        assert!(pool.contains(expected))
    }
    let expected = MacAddress::new([0x11, 0x12, 0x13, 0x14, 0x16, 0]);
    assert_eq!(
        pool.allocate(),
        MacAddress::new([0x11, 0x12, 0x13, 0x14, 0x16, 0])
    );
    assert!(pool.contains(expected));
    assert!(!pool.contains(MacAddress::new([0x11, 0x12, 0x13, 0x14, 0x16, 1])));
}

#[test]
#[should_panic(
    expected = "Mac address pool with config MacAddressPoolConfig { start: [17, 18, 19, 20, 21, 255], length: 2 }"
)]
fn depleted_pool_panics() {
    let pool = MacAddressPool::new(MacAddressPoolConfig {
        start: [0x11, 0x12, 0x13, 0x14, 0x15, 0xFF],
        length: 2,
    });

    assert_eq!(
        pool.allocate(),
        MacAddress::new([0x11, 0x12, 0x13, 0x14, 0x15, 0xFF])
    );
    assert_eq!(
        pool.allocate(),
        MacAddress::new([0x11, 0x12, 0x13, 0x14, 0x16, 0x00])
    );
    pool.allocate();
}

#[test]
fn configured_ranges_do_not_overlap() {
    for (left_index, (left_name, left_config)) in pool_configs().iter().enumerate() {
        for (right_name, right_config) in pool_configs().iter().skip(left_index + 1) {
            assert!(
                !ranges_overlap(*left_config, *right_config),
                "{left_name} overlaps {right_name}"
            );
        }
    }
}

fn pool_configs() -> [(&'static str, MacAddressPoolConfig); 8] {
    [
        ("dpu_oob", DPU_OOB_MAC_ADDRESS_POOL_CONFIG),
        ("dpu_bmc", DPU_BMC_MAC_ADDRESS_POOL_CONFIG),
        ("host", HOST_MAC_ADDRESS_POOL_CONFIG),
        ("host_bmc", HOST_BMC_MAC_ADDRESS_POOL_CONFIG),
        ("host_non_dpu", HOST_NON_DPU_MAC_ADDRESS_POOL_CONFIG),
        (
            "expected_switch_bmc",
            EXPECTED_SWITCH_BMC_MAC_ADDRESS_POOL_CONFIG,
        ),
        (
            "expected_power_shelf_bmc",
            EXPECTED_POWER_SHELF_BMC_MAC_ADDRESS_POOL_CONFIG,
        ),
        (
            "expected_switch_nvos",
            EXPECTED_SWITCH_NVOS_MAC_ADDRESS_POOL_CONFIG,
        ),
    ]
}

fn ranges_overlap(left: MacAddressPoolConfig, right: MacAddressPoolConfig) -> bool {
    let left_start = to_u64_be(left.start);
    let left_end = left_start + left.length as u64;
    let right_start = to_u64_be(right.start);
    let right_end = right_start + right.length as u64;

    left_start < right_end && right_start < left_end
}

fn to_u64_be(bytes: [u8; 6]) -> u64 {
    u64::from_be_bytes([
        0, 0, bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5],
    ])
}
