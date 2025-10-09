/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */

// Tests for common/mac_address_pool.rs
// They can't be in the common file because otherwise every test crate would also run those tests.

use common::mac_address_pool::{MacAddressPool, MacAddressPoolConfig};
use mac_address::MacAddress;

use crate::tests::common;

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
