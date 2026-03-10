// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

pub mod config;
pub mod dispatcher;
pub mod error;
pub mod mock;
pub mod nsm;
pub mod nv_switch_manager;
pub mod power_shelf_manager;
pub mod psm;

pub mod proto {
    pub mod nsm {
        tonic::include_proto!("nsm.v1");
    }
    pub mod psm {
        tonic::include_proto!("v1");
    }
}
