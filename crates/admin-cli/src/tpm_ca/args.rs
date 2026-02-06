/*
 * SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
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
