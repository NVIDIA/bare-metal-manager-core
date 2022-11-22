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

//! Contains fixtures that use the Carbide API for setting up

use std::sync::Arc;

use carbide::api::Api;

use crate::common::test_credentials::TestCredentialProvider;

pub mod dpu;
pub mod network_segment;

/// Carbide API for integration tests
pub type TestApi = Api<TestCredentialProvider>;

pub fn create_test_api(pool: sqlx::PgPool) -> TestApi {
    carbide::api::Api::new(Arc::new(TestCredentialProvider::new()), pool)
}
