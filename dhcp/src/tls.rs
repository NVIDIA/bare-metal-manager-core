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

use rpc::forge_tls_client::{ForgeClientCert, ForgeTlsConfig};

use crate::CONFIG;

pub fn build_forge_tls_config() -> ForgeTlsConfig {
    let forge_root_ca_path = &CONFIG
        .read()
        .unwrap() // safety: the only way this will panic is if the lock is poisoned,
        // which happens when another holder panics. we're already done at that point.
        .forge_root_ca_path;
    let forge_client_key_path = &CONFIG
        .read()
        .unwrap() // safety: the only way this will panic is if the lock is poisoned,
        // which happens when another holder panics. we're already done at that point.
        .forge_client_key_path;
    let forge_client_cert_path = &CONFIG
        .read()
        .unwrap() // safety: the only way this will panic is if the lock is poisoned,
        // which happens when another holder panics. we're already done at that point.
        .forge_client_cert_path;

    ForgeTlsConfig {
        root_ca_path: forge_root_ca_path.clone(),
        client_cert: Some(ForgeClientCert {
            cert_path: forge_client_cert_path.clone(),
            key_path: forge_client_key_path.clone(),
        }),
    }
}
