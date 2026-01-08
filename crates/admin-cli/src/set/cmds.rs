/*
 * SPDX-FileCopyrightText: Copyright (c) 2024-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */

use ::rpc::admin_cli::CarbideCliResult;
use ::rpc::forge::ConfigSetting;

use super::args::{BmcProxyOptions, CreateMachinesOptions, LogFilterOptions};
use crate::rpc::ApiClient;

pub async fn log_filter(opts: LogFilterOptions, api_client: &ApiClient) -> CarbideCliResult<()> {
    api_client
        .set_dynamic_config(ConfigSetting::LogFilter, opts.filter, Some(opts.expiry))
        .await
}

pub async fn create_machines(
    opts: CreateMachinesOptions,
    api_client: &ApiClient,
) -> CarbideCliResult<()> {
    api_client
        .set_dynamic_config(
            ConfigSetting::CreateMachines,
            opts.enabled.to_string(),
            None,
        )
        .await
}

pub async fn bmc_proxy(opts: BmcProxyOptions, api_client: &ApiClient) -> CarbideCliResult<()> {
    if opts.enabled {
        api_client
            .set_dynamic_config(
                ConfigSetting::BmcProxy,
                opts.proxy.unwrap_or_default(),
                None,
            )
            .await
    } else {
        api_client
            .set_dynamic_config(ConfigSetting::BmcProxy, String::new(), None)
            .await
    }
}

pub async fn tracing_enabled(value: bool, api_client: &ApiClient) -> CarbideCliResult<()> {
    api_client
        .set_dynamic_config(ConfigSetting::TracingEnabled, value.to_string(), None)
        .await
}
