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

use health_report::HealthProbeId;

lazy_static::lazy_static! {
    pub static ref ContainerExists: HealthProbeId = "ContainerExists".parse().unwrap();
    pub static ref SupervisorctlStatus: HealthProbeId = "SupervisorctlStatus".parse().unwrap();
    pub static ref ServiceRunning: HealthProbeId = "ServiceRunning".parse().unwrap();
    pub static ref DhcpRelay: HealthProbeId = "DhcpRelay".parse().unwrap();
    pub static ref DhcpServer: HealthProbeId = "DhcpServer".parse().unwrap();
    pub static ref BgpStats: HealthProbeId = "BgpStats".parse().unwrap();
    pub static ref BgpPeeringTor: HealthProbeId = "BgpPeeringTor".parse().unwrap();
    pub static ref BgpPeeringRouteServer: HealthProbeId = "BgpPeeringRouteServer".parse().unwrap();
    pub static ref UnexpectedBgpPeer: HealthProbeId = "UnexpectedBgpPeer".parse().unwrap();
    pub static ref Ifreload: HealthProbeId = "Ifreload".parse().unwrap();
    pub static ref FileExists: HealthProbeId = "FileExists".parse().unwrap();
    pub static ref FileIsValid: HealthProbeId = "FileIsValid".parse().unwrap();
    pub static ref BgpDaemonEnabled: HealthProbeId = "BgpDaemonEnabled".parse().unwrap();
    pub static ref RestrictedMode: HealthProbeId = "RestrictedMode".parse().unwrap();
    pub static ref PostConfigCheckWait: HealthProbeId = "PostConfigCheckWait".parse().unwrap();
    pub static ref DpuDiskUtilizationCheck: HealthProbeId = "DpuDiskUtilizationCheck".parse().unwrap();
    pub static ref DpuDiskUtilizationCritical: HealthProbeId = "DpuDiskUtilizationCritical".parse().unwrap();
}
