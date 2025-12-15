/*
 * SPDX-FileCopyrightText: Copyright (c) 2022-2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */

use clap::Parser;

#[derive(Parser, Debug)]
pub enum Cmd {
    #[clap(about = "Show all TPM CA certificates")]
    Show,
    #[clap(about = "Delete TPM CA certificate with a given id")]
    Delete(TpmCaDbId),
    #[clap(about = "Add TPM CA certificate encoded in DER/CER/PEM format in a given file")]
    Add(TpmCaFile),
    #[clap(about = "Show TPM EK certificates for which there is no CA match")]
    ShowUnmatchedEk,
    #[clap(about = "Add all certificates in a dir as CA certificates")]
    AddBulk(TpmCaDir),
}

#[derive(Parser, Debug)]
pub struct TpmCaDir {
    #[clap(short, long, help = "Directory path containing all CA certs")]
    pub dirname: String,
}

#[derive(Parser, Debug)]
pub struct TpmCaDbId {
    #[clap(short, long, help = "TPM CA id obtained from the show command")]
    pub ca_id: i32,
}

#[derive(Parser, Debug)]
pub struct TpmCaFile {
    #[clap(short, long, help = "File name containing certificate in DER format")]
    pub filename: String,
}
