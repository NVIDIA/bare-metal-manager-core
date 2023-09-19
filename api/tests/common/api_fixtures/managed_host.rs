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

use carbide::model::hardware_info::TpmEkCertificate;
use mac_address::MacAddress;

/// Describes the a Managed Host
#[derive(Debug, Clone)]
pub struct ManagedHostConfig {
    pub dpu_oob_mac_address: MacAddress,
    pub dpu_bmc_mac_address: MacAddress,
    pub host_mac_address: MacAddress,
    pub host_bmc_mac_address: MacAddress,
    pub host_tpm_ek_cert: TpmEkCertificate,
}

#[derive(Debug)]
pub struct ManagedHostSim {
    pub config: ManagedHostConfig,
}
