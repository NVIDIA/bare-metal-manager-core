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
use std::env;

/// check and make sure libipmiconsole and libipmiconsole headers are installed
fn main() {
    let statik = env::var("CARGO_FEATURE_STATIC").is_ok();

    let _libipmiconsole = pkg_config::Config::new()
        .cargo_metadata(false)
        .statik(statik)
        .probe("libipmiconsole")
        .unwrap();
}
