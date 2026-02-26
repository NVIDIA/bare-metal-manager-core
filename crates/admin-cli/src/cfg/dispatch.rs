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

use ::rpc::admin_cli::CarbideCliResult;

use crate::cfg::runtime::RuntimeContext;

// Dispatch is a trait implemented by all CLI command types.
// It provides a unified interface for executing commands with
// the runtime context.
pub(crate) trait Dispatch {
    fn dispatch(
        self,
        ctx: RuntimeContext,
    ) -> impl std::future::Future<Output = CarbideCliResult<()>>;
}

// Re-export the derive macro so modules can import both the
// trait and derive with: use crate::cfg::dispatch::Dispatch;
pub(crate) use carbide_macros::Dispatch;

#[cfg(test)]
mod tests {
    use ::rpc::admin_cli::CarbideCliResult;

    use super::Dispatch;
    use crate::cfg::run::Run;
    use crate::cfg::runtime::RuntimeContext;

    // Stub leaf command type that implements Run for the purpose
    // of testing our Dispatch + Run trait handling flow.
    struct StubRunArgs;

    impl Run for StubRunArgs {
        async fn run(self, _ctx: &mut RuntimeContext) -> CarbideCliResult<()> {
            Ok(())
        }
    }

    // Stub nested command group that implements Dispatch, also for
    // the purpose of testing our Dispatch + Run trait handling flow.
    struct StubNestedCmd;

    impl Dispatch for StubNestedCmd {
        async fn dispatch(self, _ctx: RuntimeContext) -> CarbideCliResult<()> {
            Ok(())
        }
    }

    // Verify the derive generates a valid Dispatch impl when
    // all variants are "leaf" commands (i.e. the Run trait).
    #[derive(Dispatch)]
    #[allow(dead_code)]
    enum AllRunCmd {
        CmdA(StubRunArgs),
        CmdB(StubRunArgs),
        CmdC(StubRunArgs),
    }

    // Verify the derive generates a valid Dispatch impl when
    // mixing "leaf" commands (the `Run` trait) with nested command
    // groups (which we annotate inline with `#[dispatch]`).
    #[derive(Dispatch)]
    #[allow(dead_code)]
    enum MixedCmd {
        SimpleRunCommand(StubRunArgs),
        #[dispatch]
        NestedCommandGroup(StubNestedCmd),
    }

    fn assert_dispatch<T: Dispatch>() {}

    #[test]
    fn all_run_variants_derive_dispatch() {
        assert_dispatch::<AllRunCmd>();
    }

    #[test]
    fn mixed_run_and_dispatch_variants_derive_dispatch() {
        assert_dispatch::<MixedCmd>();
    }
}
