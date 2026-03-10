// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

fn main() -> Result<(), Box<dyn std::error::Error>> {
    tonic_prost_build::configure().compile_protos(
        &[
            "proto/nvswitch-manager.proto",
            "proto/powershelf-manager.proto",
        ],
        &["proto/"],
    )?;
    Ok(())
}
