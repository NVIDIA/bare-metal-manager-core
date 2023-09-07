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

pub use crate::db::resource_pool::{
    all, find_value, stats, DbResourcePool, OwnerType, ResourcePoolError, ResourcePoolStats,
    ValueType,
};
pub mod common;
mod define;
pub use define::{
    define_all_from, DefineResourcePoolError, Range, ResourcePoolDef, ResourcePoolType,
};
