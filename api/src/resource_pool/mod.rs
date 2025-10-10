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

pub(crate) mod common;
pub(crate) mod define;
pub use define::ResourcePoolDef;
pub(crate) use define::{DefineResourcePoolError, define_all_from};
// These are currently only used by api-test
#[cfg(test)]
pub use define::{Range, ResourcePoolType};
pub(crate) use model::resource_pool::{OwnerType, ResourcePool, ResourcePoolError, ValueType};

pub(crate) use crate::db::resource_pool::{all, find_value, stats};
