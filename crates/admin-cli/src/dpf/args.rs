/*
 * SPDX-FileCopyrightText: Copyright (c) 2022 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */

use carbide_uuid::machine::MachineId;
use clap::Parser;

#[derive(Parser, Debug)]
pub enum Cmd {
    #[clap(about = "Enable DPF")]
    Enable(DpfQuery),
    #[clap(about = "Disable DPF")]
    Disable(DpfQuery),
    #[clap(about = "Check Status of DPF")]
    Show(DpfQuery),
}

#[derive(Parser, Debug)]
pub struct DpfQuery {
    #[clap(required(true), help = "Host machine id")]
    pub host: Option<MachineId>,
}
