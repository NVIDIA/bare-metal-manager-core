/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */

// Define the sqlx_fixture_from_str function, which is used by the `#[crate::sqlx_test]` proc-macro.
// Use a macro to avoid having to paste every filename in 3 places.
#[macro_export]
macro_rules! define_sqlx_fixtures {
    ( $($file:expr),* $(,)? ) => {
        pub fn sqlx_fixture_from_str(s: &str) -> sqlx::testing::TestFixture {
            match s {
                $(
                    $file => sqlx::testing::TestFixture {
                        path: concat!("../fixtures/", $file, ".sql"),
                        contents: include_str!(concat!("../fixtures/", $file, ".sql")),
                    },
                )*
                _ => panic!("Invalid fixture name"),
            }
        }
    };
}

define_sqlx_fixtures!(
    "create_cred_pub_key",
    "create_cred_pub_key_invalid",
    "create_dpu_remediation",
    "create_expected_machine",
    "create_expected_power_shelf",
    "create_machine_validation_tests",
    "create_tpm_ca_cert_invalid",
    "create_tpm_ca_wrong_cert",
    "create_sku",
    "create_expected_machine_no_default_poweron"
);
