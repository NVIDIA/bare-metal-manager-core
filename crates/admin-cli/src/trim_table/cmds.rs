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

use super::args::KeepEntries;
use crate::rpc::ApiClient;

pub async fn trim_measured_boot(args: KeepEntries, api_client: &ApiClient) -> CarbideCliResult<()> {
    let request = ::rpc::forge::TrimTableRequest {
        target: ::rpc::forge::TrimTableTarget::MeasuredBoot.into(),
        keep_entries: args.keep_entries,
    };

    let response = api_client.0.trim_table(request).await?;

    println!(
        "Trimmed {} reports from Measured Boot",
        response.total_deleted
    );
    Ok(())
}
