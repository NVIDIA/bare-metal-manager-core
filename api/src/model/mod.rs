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

//! Describes the Forge site controller internal data model
//!
//! The model described here is used in both internal decision logic and might
//! be stored in database fields.
//! Data inside this module therefore needs to be backward compatible with previous
//! versions of Forge that are deployed.
//!
//! The module should only contain data definitions and associated helper functions,
//! but no actual business logic.

pub mod config_version;
pub mod hardware_info;
pub mod instance;
pub mod machine;

/// Enumerates errors that can occur when converting from the RPC data format
/// into the internal data model
#[derive(Debug, thiserror::Error)]
pub enum RpcDataConversionError {
    #[error("Field {0} is not valid base64")]
    InvalidBase64Data(&'static str),
}

/// Converts a `Vec<T>` of any type `T` that is convertible to a type `R`
/// into a `Vec<R>`.
pub fn try_convert_vec<T, R, E>(source: Vec<T>) -> Result<Vec<R>, E>
where
    R: TryFrom<T, Error = E>,
{
    source.into_iter().map(R::try_from).collect()
}
