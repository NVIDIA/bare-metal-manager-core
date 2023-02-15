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
use carbide::auth::{Authorizer, NoopEngine};
use carbide::kubernetes::VpcApiSim;

use crate::common::test_credentials::TestCredentialProvider;

pub mod dpu;
pub mod host;
pub mod instance;
pub mod network_segment;

/// Carbide API for integration tests
pub type TestApi = Api<TestCredentialProvider>;

pub const FIXTURE_DOMAIN_ID: uuid::Uuid = uuid::uuid!("1ebec7c1-114f-4793-a9e4-63f3d22b5b5e");

pub fn create_test_api(pool: sqlx::PgPool) -> TestApi {
    // TODO: Some tests might require a shared VpcApiSim with the state machine
    // for consistency. This means we need to create the sim upfront and share it
    // here. We will change this in a follow-up, since it requires touching a lot
    // of tests
    carbide::api::Api::new(
        Arc::new(TestCredentialProvider::new()),
        pool,
        Authorizer::new(Arc::new(NoopEngine {})),
        Arc::new(VpcApiSim::default()),
    )
}
