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

/// Where we bake the root CA in our containers
pub const ROOT_CA: &str = "/opt/forge/forge_root.pem";

pub fn default_root_ca() -> &'static str {
    ROOT_CA
}

/// Where we write the client cert in our clients
pub const CLIENT_CERT: &str = "/opt/forge/machine_cert.pem";

pub fn default_client_cert() -> &'static str {
    CLIENT_CERT
}

/// Where we write the client key in our clients
pub const CLIENT_KEY: &str = "/opt/forge/machine_cert.key";

pub fn default_client_key() -> &'static str {
    CLIENT_KEY
}
