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

#[allow(non_snake_case, unknown_lints, clippy::all)]
#[rustfmt::skip]
pub mod common;

#[allow(non_snake_case, unknown_lints, clippy::all)]
#[rustfmt::skip]
pub mod forge;

#[allow(non_snake_case, unknown_lints, clippy::all)]
#[rustfmt::skip]
pub mod health;

#[allow(non_snake_case, unknown_lints, clippy::all)]
#[rustfmt::skip]
pub mod machine_discovery;

#[allow(non_snake_case, unknown_lints, clippy::all)]
#[rustfmt::skip]
pub mod measured_boot;

#[allow(non_snake_case, unknown_lints, clippy::all)]
#[rustfmt::skip]
pub mod mlx_device;

#[allow(non_snake_case, unknown_lints, clippy::all)]
#[rustfmt::skip]
pub mod site_explorer;

#[allow(non_snake_case, unknown_lints, clippy::all)]
#[rustfmt::skip]
pub mod dns;

#[allow(clippy::all, deprecated)]
#[rustfmt::skip]
pub mod forge_api_client;

#[allow(clippy::all)]
#[rustfmt::skip]
pub mod convenience_converters;

#[allow(non_snake_case, unknown_lints, clippy::all)]
#[rustfmt::skip]
pub mod dpa_rpc;


#[allow(clippy::all)]
#[rustfmt::skip]
pub mod rack_manager;

#[allow(clippy::all)]
#[rustfmt::skip]
pub mod rack_manager_client;

#[allow(clippy::all)]
#[rustfmt::skip]
pub mod rack_manager_converters;

#[allow(clippy::all)]
#[rustfmt::skip]
pub mod nmx_c;

#[allow(clippy::all)]
#[rustfmt::skip]
pub mod nmx_c_client;

#[allow(clippy::all)]
#[rustfmt::skip]
pub mod nmx_c_converters;
