/*
 * SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

use std::path::PathBuf;

use clap::Parser;

#[derive(Parser, Debug, Clone)]
pub(crate) enum Args {
    #[clap(about = "Set or rotate a firmware artifact access token")]
    Set(SetArgs),
    #[clap(about = "Delete a firmware artifact access token")]
    Delete(DeleteArgs),
}

#[derive(Parser, Debug, Clone)]
#[command(after_long_help = "\
EXAMPLES:

Set a token from standard input:
    $ printf '%s' \"$TOKEN\" | nico-admin-cli credential firmware-access-token set --name repository-a --token-file -

")]
pub(crate) struct SetArgs {
    #[arg(long, help = "Non-secret credential name")]
    pub(super) name: String,

    #[arg(
        long,
        help = "File containing the token, or '-' to read standard input"
    )]
    pub(super) token_file: PathBuf,
}

#[derive(Parser, Debug, Clone)]
#[command(after_long_help = "\
EXAMPLES:

Delete a token:
    $ nico-admin-cli credential firmware-access-token delete --name repository-a

")]
pub(crate) struct DeleteArgs {
    #[arg(long, help = "Non-secret credential name")]
    pub(super) name: String,
}
