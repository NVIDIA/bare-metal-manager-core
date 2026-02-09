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
