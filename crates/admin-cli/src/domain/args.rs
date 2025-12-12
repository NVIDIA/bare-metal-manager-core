/*
 * SPDX-FileCopyrightText: Copyright (c) 2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */

use carbide_uuid::domain::DomainId;
use clap::Parser;

#[derive(Parser, Debug)]
pub enum Cmd {
    #[clap(about = "Display Domain information")]
    Show(ShowDomain),
}

#[derive(Parser, Debug)]
pub struct ShowDomain {
    #[clap(
        short,
        long,
        action,
        conflicts_with = "domain",
        help = "Show all domains (DEPRECATED)"
    )]
    pub all: bool,

    #[clap(
        default_value(None),
        help = "The domain to query, leave empty for all (default)"
    )]
    pub domain: Option<DomainId>,
}
