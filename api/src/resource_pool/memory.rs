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
use std::cmp::Ord;
use std::str::FromStr;
use std::sync::Mutex;

use super::{ResourcePool, ResourcePoolError};

/// An in-memory version of ResourcePool for unit testing
pub struct MemoryResourcePool<T: Send + Sync> {
    values: Mutex<Pools<T>>,
}

struct Pools<T: Send + Sync> {
    available: Vec<T>,
    used: Vec<T>,
}

impl<T: Send + Sync> MemoryResourcePool<T> {
    pub fn new() -> MemoryResourcePool<T> {
        MemoryResourcePool {
            values: Mutex::new(Pools {
                available: Vec::new(),
                used: Vec::new(),
            }),
        }
    }
}

impl<T: Send + Sync> Default for MemoryResourcePool<T> {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl<T> ResourcePool<T> for MemoryResourcePool<T>
where
    T: ToString + FromStr + Ord + Send + Sync + PartialEq + Clone,
{
    async fn populate(&self, mut values: Vec<T>) -> Result<(), ResourcePoolError> {
        let mut pools = self.values.lock().unwrap();
        pools.available.append(&mut values);
        pools.available.sort_unstable();
        pools.available.dedup();

        Ok(())
    }

    async fn allocate(&self, _: super::OwnerType, _: &str) -> Result<T, ResourcePoolError> {
        let mut pools = self.values.lock().unwrap();
        let v = pools.available.pop().ok_or(ResourcePoolError::Empty)?;
        pools.used.push(v.clone());
        Ok(v)
    }

    async fn release(&self, value: T) -> Result<(), ResourcePoolError> {
        let mut pools = self.values.lock().unwrap();
        let idx = pools
            .used
            .iter()
            .position(|x| *x == value)
            .ok_or(ResourcePoolError::NotAllocated)?;
        let v = pools.used.swap_remove(idx);
        pools.available.push(v);
        Ok(())
    }

    async fn stats(&self) -> Result<super::ResourcePoolStats, ResourcePoolError> {
        let v = self.values.lock().unwrap();
        Ok(super::ResourcePoolStats {
            used: v.used.len(),
            free: v.available.len(),
        })
    }

    // The opposite of release
    async fn mark_allocated(
        &self,
        value: T,
        _owner_type: super::OwnerType,
        _owner_id: &str,
    ) -> Result<(), ResourcePoolError> {
        let mut pools = self.values.lock().unwrap();
        let idx = pools
            .available
            .iter()
            .position(|x| *x == value)
            .ok_or(ResourcePoolError::NotAvailable)?;
        let v = pools.available.swap_remove(idx);
        pools.used.push(v);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::MemoryResourcePool;
    use crate::resource_pool::{OwnerType, ResourcePool, ResourcePoolStats};

    #[tokio::test]
    async fn test_memory_pool() -> Result<(), Box<dyn std::error::Error>> {
        let pool = MemoryResourcePool::new();

        pool.populate(vec![1, 2, 3, 4]).await?;
        assert_eq!(pool.stats().await?, ResourcePoolStats { used: 0, free: 4 });

        let v = pool.allocate(OwnerType::Machine, "my_id").await?;
        if !(1..=4).contains(&v) {
            panic!("Memory pool allocated an impossible value");
        }
        assert_eq!(pool.stats().await?, ResourcePoolStats { used: 1, free: 3 });

        pool.release(v).await?;
        assert_eq!(pool.stats().await?, ResourcePoolStats { used: 0, free: 4 });

        pool.populate(vec![4, 5, 6]).await?;
        assert_eq!(pool.stats().await?, ResourcePoolStats { used: 0, free: 6 });

        Ok(())
    }
}
