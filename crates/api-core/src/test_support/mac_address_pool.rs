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

use carbide_utils::test_support::mac_address_pool as mock_mac_pool;
use mac_address::MacAddress;
pub use mock_mac_pool::MacAddressPoolConfig;

pub const DPU_OOB_MAC_ADDRESS_POOL_CONFIG: MacAddressPoolConfig = MacAddressPoolConfig {
    start: [0x11, 0x11, 0x11, 0x11, 0x0, 0x0],
    length: 65536,
};

pub const DPU_BMC_MAC_ADDRESS_POOL_CONFIG: MacAddressPoolConfig = MacAddressPoolConfig {
    start: [0x11, 0x11, 0x22, 0x22, 0x0, 0x0],
    length: 65536,
};

pub const HOST_MAC_ADDRESS_POOL_CONFIG: MacAddressPoolConfig = MacAddressPoolConfig {
    start: [0x22, 0x22, 0x11, 0x11, 0x0, 0x0],
    length: 65536,
};

pub const HOST_BMC_MAC_ADDRESS_POOL_CONFIG: MacAddressPoolConfig = MacAddressPoolConfig {
    start: [0x22, 0x22, 0x22, 0x22, 0x0, 0x0],
    length: 65536,
};

pub const HOST_NON_DPU_MAC_ADDRESS_POOL_CONFIG: MacAddressPoolConfig = MacAddressPoolConfig {
    start: [0x33, 0x33, 0x11, 0x11, 0x0, 0x0],
    length: 65536,
};

pub const EXPECTED_SWITCH_BMC_MAC_ADDRESS_POOL_CONFIG: MacAddressPoolConfig =
    MacAddressPoolConfig {
        start: [0x44, 0x44, 0x11, 0x11, 0x0, 0x0],
        length: 65536,
    };

pub const EXPECTED_POWER_SHELF_BMC_MAC_ADDRESS_POOL_CONFIG: MacAddressPoolConfig =
    MacAddressPoolConfig {
        start: [0x44, 0x44, 0x22, 0x22, 0x0, 0x0],
        length: 65536,
    };

pub const EXPECTED_SWITCH_NVOS_MAC_ADDRESS_POOL_CONFIG: MacAddressPoolConfig =
    MacAddressPoolConfig {
        start: [0x44, 0x44, 0x33, 0x33, 0x0, 0x0],
        length: 65536,
    };

#[derive(Debug)]
pub struct MacAddressPool {
    inner: mock_mac_pool::MacAddressPool,
}

impl MacAddressPool {
    pub fn new(config: MacAddressPoolConfig) -> Self {
        Self {
            inner: mock_mac_pool::MacAddressPool::new(config),
        }
    }

    /// Allocates a unique MAC address from the pool
    ///
    /// Will panic once the pool is depleted
    pub fn allocate(&self) -> MacAddress {
        self.inner
            .allocate()
            .unwrap_or_else(|error| panic!("{error}"))
    }

    /// Returns whether an address is part of the pool
    pub fn contains(&self, address: MacAddress) -> bool {
        self.inner.contains(address)
    }
}

lazy_static::lazy_static! {
    /// Pool of DPU MAC addresses
    pub static ref DPU_OOB_MAC_ADDRESS_POOL: MacAddressPool =
        MacAddressPool::new(DPU_OOB_MAC_ADDRESS_POOL_CONFIG);

    /// Pool of DPU BMC MAC addresses
    pub static ref DPU_BMC_MAC_ADDRESS_POOL: MacAddressPool =
        MacAddressPool::new(DPU_BMC_MAC_ADDRESS_POOL_CONFIG);

    /// Pool of Host MAC addresses
    pub static ref HOST_MAC_ADDRESS_POOL: MacAddressPool =
        MacAddressPool::new(HOST_MAC_ADDRESS_POOL_CONFIG);

    /// Pool of Host BMC MAC addresses
    pub static ref HOST_BMC_MAC_ADDRESS_POOL: MacAddressPool =
        MacAddressPool::new(HOST_BMC_MAC_ADDRESS_POOL_CONFIG);

    /// Pool of Host non-DPU MAC addresses
    pub static ref HOST_NON_DPU_MAC_ADDRESS_POOL: MacAddressPool =
        MacAddressPool::new(HOST_NON_DPU_MAC_ADDRESS_POOL_CONFIG);

    /// Pool of Expected Switch BMC MAC addresses
    pub static ref EXPECTED_SWITCH_BMC_MAC_ADDRESS_POOL: MacAddressPool =
        MacAddressPool::new(EXPECTED_SWITCH_BMC_MAC_ADDRESS_POOL_CONFIG);

    /// Pool of Expected Power Shelf BMC MAC addresses
    pub static ref EXPECTED_POWER_SHELF_BMC_MAC_ADDRESS_POOL: MacAddressPool =
        MacAddressPool::new(EXPECTED_POWER_SHELF_BMC_MAC_ADDRESS_POOL_CONFIG);

    /// Pool of Expected Switch NVOS MAC addresses
    pub static ref EXPECTED_SWITCH_NVOS_MAC_ADDRESS_POOL: MacAddressPool =
        MacAddressPool::new(EXPECTED_SWITCH_NVOS_MAC_ADDRESS_POOL_CONFIG);
}
