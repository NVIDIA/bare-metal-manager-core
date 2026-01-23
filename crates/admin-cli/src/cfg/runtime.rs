/*
 * SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */

use std::pin::Pin;

use rpc::admin_cli::OutputFormat;

use crate::cfg::cli_options::SortField;
use crate::rpc::{ApiClient, RmsApiClient};

// RuntimeContext is context passed to all subcommand
// dispatch handlers. This is built at the beginning of
// runtime and then passed to the appropriate dispatcher.
pub struct RuntimeContext {
    pub api_client: ApiClient,
    pub config: RuntimeConfig,
    pub output_file: Pin<Box<dyn tokio::io::AsyncWrite>>,
    pub rms_client: RmsApiClient,
}

// RuntimeConfig contains runtime configuration parameters extracted
// from CLI options. This should contain the entirety of any options
// that need to be leveraged by any downstream command handler.
pub struct RuntimeConfig {
    pub format: OutputFormat,
    pub page_size: usize,
    pub extended: bool,
    pub cloud_unsafe_op_enabled: bool,
    pub sort_by: SortField,
}
