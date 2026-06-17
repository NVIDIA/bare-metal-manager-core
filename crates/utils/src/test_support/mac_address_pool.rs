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

use std::fmt;
use std::sync::atomic::{AtomicUsize, Ordering};

use mac_address::MacAddress;
use serde::{Deserialize, Serialize};

#[derive(Copy, Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct MacAddressPoolConfig {
    /// The first MAC address in the pool as a byte array.
    pub start: [u8; 6],
    /// The number of addresses in the pool.
    pub length: usize,
}

#[derive(Debug, Eq, PartialEq)]
pub enum MacAddressPoolError {
    Depleted {
        config: MacAddressPoolConfig,
        attempted_offset: usize,
    },
}

impl fmt::Display for MacAddressPoolError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MacAddressPoolError::Depleted { config, .. } => {
                write!(f, "Mac address pool with config {config:?} is depleted")
            }
        }
    }
}

impl std::error::Error for MacAddressPoolError {}

#[derive(Debug)]
pub struct MacAddressPool {
    config: MacAddressPoolConfig,
    used: AtomicUsize,
}

impl MacAddressPool {
    pub const fn new(config: MacAddressPoolConfig) -> Self {
        Self {
            config,
            used: AtomicUsize::new(0),
        }
    }

    pub fn config(&self) -> MacAddressPoolConfig {
        self.config
    }

    pub fn allocate(&self) -> Result<MacAddress, MacAddressPoolError> {
        loop {
            let offset = self.used.load(Ordering::SeqCst);
            if offset >= self.config.length {
                return Err(MacAddressPoolError::Depleted {
                    config: self.config,
                    attempted_offset: offset,
                });
            }

            if self
                .used
                .compare_exchange(offset, offset + 1, Ordering::SeqCst, Ordering::SeqCst)
                .is_ok()
            {
                return Ok(mac_address_at_offset(self.config.start, offset));
            }
        }
    }

    pub fn contains(&self, address: MacAddress) -> bool {
        let address = to_u64_be(address.bytes());
        let min = to_u64_be(self.config.start);
        let Some(max) = min.checked_add(self.config.length as u64) else {
            return false;
        };

        (min..max).contains(&address)
    }
}

fn mac_address_at_offset(start: [u8; 6], offset: usize) -> MacAddress {
    let u64_address = to_u64_be(start) + offset as u64;
    let mut bytes = [0u8; 6];
    bytes.copy_from_slice(&u64_address.to_be_bytes()[2..8]);
    MacAddress::new(bytes)
}

fn to_u64_be(bytes: [u8; 6]) -> u64 {
    u64::from_be_bytes([
        0, 0, bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5],
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allocate_addresses() {
        let pool = MacAddressPool::new(MacAddressPoolConfig {
            start: [0x11, 0x12, 0x13, 0x14, 0x15, 0x1],
            length: 256,
        });
        assert!(!pool.contains(MacAddress::new([0x11, 0x12, 0x13, 0x14, 0x15, 0])));

        for i in 1..=255 {
            let expected = MacAddress::new([0x11, 0x12, 0x13, 0x14, 0x15, i as u8]);
            assert_eq!(pool.allocate().unwrap(), expected);
            assert!(pool.contains(expected));
        }
        let expected = MacAddress::new([0x11, 0x12, 0x13, 0x14, 0x16, 0]);
        assert_eq!(pool.allocate().unwrap(), expected);
        assert!(pool.contains(expected));
        assert!(!pool.contains(MacAddress::new([0x11, 0x12, 0x13, 0x14, 0x16, 1])));
    }

    #[test]
    fn depleted_pool_returns_error() {
        let config = MacAddressPoolConfig {
            start: [0x11, 0x12, 0x13, 0x14, 0x15, 0xFF],
            length: 2,
        };
        let pool = MacAddressPool::new(config);

        assert_eq!(
            pool.allocate().unwrap(),
            MacAddress::new([0x11, 0x12, 0x13, 0x14, 0x15, 0xFF])
        );
        assert_eq!(
            pool.allocate().unwrap(),
            MacAddress::new([0x11, 0x12, 0x13, 0x14, 0x16, 0x00])
        );
        assert_eq!(
            pool.allocate(),
            Err(MacAddressPoolError::Depleted {
                config,
                attempted_offset: 2,
            })
        );
    }
}
