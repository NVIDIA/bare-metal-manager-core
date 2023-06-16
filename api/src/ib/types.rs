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

pub const IBNETWORK_DEFAULT_MEMBERSHIP: IBPortMembership = IBPortMembership::Full;
pub const IBNETWORK_DEFAULT_INDEX0: bool = true;

#[derive(Clone)]
pub struct IBNetwork {
    /// The name of IB network.
    pub name: String,
    /// The pkey of IB network.
    pub pkey: i32,
    /// Default false; create sharp allocation accordingly.
    pub enable_sharp: bool,
    /// Default 2k; one of 2k or 4k; the MTU of the services.
    pub mtu: u16,
    /// Default false
    pub ipoib: bool,
    /// Default is None, value can be range from 0-15.
    pub service_level: u8,
    /// The default membership of IB network.
    pub membership: IBPortMembership,
    /// The default index0 of IB network.
    pub index0: bool,
    /// Default is None, can be one of the following: 2.5, 10, 30, 5, 20, 40, 60, 80, 120, 14, 56, 112, 168, 25, 100, 200, or 300.
    pub rate_limit: f64,
}

#[derive(Clone)]
pub enum IBPortState {
    Active,
    Down,
}

#[derive(Clone)]
pub enum IBPortMembership {
    Full,
    Limited,
}

#[derive(Clone)]
pub struct IBPort {
    pub name: String,
    pub guid: String,
    pub state: Option<IBPortState>,
}
