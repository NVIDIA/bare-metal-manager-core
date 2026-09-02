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
use rpc::dns::CreateDomainRequest;

#[derive(Parser, Debug)]
#[command(after_long_help = "\
EXAMPLES:

Create a DNS domain:
    $ nico-admin-cli domain create --name site.example.com

")]
pub(crate) struct Args {
    #[clap(long, help = "Name of the DNS domain to create")]
    name: String,
}

impl From<Args> for CreateDomainRequest {
    fn from(args: Args) -> Self {
        Self { name: args.name }
    }
}

#[cfg(test)]
mod tests {
    use clap::Parser;
    use rpc::dns::CreateDomainRequest;

    use super::Args;

    #[test]
    fn parses_name_into_create_request() {
        let args = Args::try_parse_from(["create", "--name", "site.example.com"])
            .expect("valid Domain create arguments should parse");
        let request = CreateDomainRequest::from(args);

        assert_eq!(request.name, "site.example.com");
    }

    #[test]
    fn requires_name() {
        let error = Args::try_parse_from(["create"])
            .expect_err("Domain create without --name should fail to parse");

        assert_eq!(
            error.kind(),
            clap::error::ErrorKind::MissingRequiredArgument
        );
    }
}
