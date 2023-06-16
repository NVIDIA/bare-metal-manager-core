/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2022 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use crate::CarbideError;

pub use self::iface::IBFabricManager;

mod iface;
mod local;
mod rest;
mod ufmclient;

pub mod pool;
pub mod types;

pub fn local_ib_fabric_manager() -> Arc<dyn IBFabricManager> {
    Arc::new(local::LocalIBFabricManager {
        ibsubnets: Arc::new(Mutex::new(HashMap::new())),
        ibports: Arc::new(Mutex::new(HashMap::new())),
    })
}

pub async fn connect(addr: &str, token: &str) -> Result<Arc<dyn IBFabricManager>, CarbideError> {
    rest::connect(addr, token).await
}
