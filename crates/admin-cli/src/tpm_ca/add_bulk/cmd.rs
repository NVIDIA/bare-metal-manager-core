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

use std::fs;
use std::path::Path;

use super::super::add::cmd::add_individual;
use crate::ca_cert_file::is_ca_cert_file;
use crate::errors::CarbideCliResult;
use crate::rpc::ApiClient;

pub async fn add_bulk(dirname: &str, api_client: &ApiClient) -> CarbideCliResult<()> {
    let dirpath = Path::new(dirname);

    // read all files ending with .cer/.der
    // call add individually for each one of them

    let dir_entry_iter = fs::read_dir(dirpath)
        .map_err(crate::errors::CarbideCliError::IOError)?
        .flatten();

    for dir_entry in dir_entry_iter {
        if is_ca_cert_file(&dir_entry.path())
            && let Err(e) = add_individual(dir_entry.path().as_path(), api_client).await
        {
            // we log the error but continue the iteration
            eprintln!("Could not add ca cert {dir_entry:?}: {e}");
        }
    }

    Ok(())
}
