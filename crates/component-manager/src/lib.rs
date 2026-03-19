// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

pub mod component_manager;
pub mod config;
pub mod error;
pub mod mock;
pub mod nsm;
pub mod nv_switch_manager;
pub mod power_shelf_manager;
pub mod psm;
pub mod tls;
pub mod types;

pub mod proto {
    #[allow(clippy::enum_variant_names)]
    pub mod nsm {
        include!(concat!(env!("OUT_DIR"), "/nsm/v1.rs"));
    }
    #[allow(clippy::enum_variant_names)]
    pub mod psm {
        include!(concat!(env!("OUT_DIR"), "/psm/v1.rs"));
    }
}
