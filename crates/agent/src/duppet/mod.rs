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

#[macro_use]
mod log;

#[cfg(test)]
mod tests;

pub mod options;
mod status;
mod sync;

pub use options::{FileEnsure, FileSpec, SummaryFormat, SyncOptions};
pub use status::SyncStatus;
pub use sync::{sync, sync_file};
