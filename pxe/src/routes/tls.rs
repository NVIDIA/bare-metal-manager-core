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

// Rust somewhere 1.71->1.76 added a lint that doesn't like Rocket
#![allow(unused_imports)]

use crate::RuntimeConfig;
use rocket::{fs::NamedFile, get, routes, Route};

#[get("/root_ca")]
pub async fn root_ca(config: RuntimeConfig) -> Option<NamedFile> {
    NamedFile::open(config.forge_root_ca_path).await.ok()
}

pub fn routes() -> Vec<Route> {
    routes![root_ca]
}
