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

use ::rpc::admin_cli::CarbideCliResult;

use crate::cfg::runtime::RuntimeContext;

// Dispatch is a trait implemented by all CLI command types.
// It provides a unified interface for executing commands with
// the runtime context.
pub(crate) trait Dispatch {
    fn dispatch(
        self,
        ctx: RuntimeContext,
    ) -> impl std::future::Future<Output = CarbideCliResult<()>>;
}
