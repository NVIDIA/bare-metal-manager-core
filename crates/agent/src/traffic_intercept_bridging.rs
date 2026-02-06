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

use eyre::WrapErr;
use gtmpl_derive::Gtmpl;

pub const SAVE_PATH: &str = "/tmp/update_intercept_bridging.sh";

const TMPL_BRIDGING: &str = include_str!("../templates/update_intercept_bridging.sh.tmpl");

// What we need for the commands to configure the bridge.
pub struct TrafficInterceptBridgingConfig {
    pub secondary_overlay_vtep_ip: String,
    pub vf_intercept_bridge_ip: String,
    pub vf_intercept_bridge_name: String,
    pub intercept_bridge_prefix_len: u8,
}

//
// Go template objects, hence allow(non_snake_case)
//

#[allow(non_snake_case)]
#[derive(Clone, Gtmpl, Debug)]
struct TmplTrafficInterceptBridging {
    SecondaryOverlayVtepIP: String,
    VfInterceptBridgeIP: String,
    VfInterceptBridgeName: String,
    InterceptBridgePrefixLen: u8,
}

pub fn build(conf: TrafficInterceptBridgingConfig) -> eyre::Result<String> {
    let params = TmplTrafficInterceptBridging {
        SecondaryOverlayVtepIP: conf.secondary_overlay_vtep_ip,
        VfInterceptBridgeIP: conf.vf_intercept_bridge_ip,
        VfInterceptBridgeName: conf.vf_intercept_bridge_name,
        InterceptBridgePrefixLen: conf.intercept_bridge_prefix_len,
    };

    gtmpl::template(TMPL_BRIDGING, params).map_err(|e| {
        println!("ERR filling template: {e}",);
        e.into()
    })
}

pub async fn apply(sh_path: &super::FPath) -> eyre::Result<()> {
    match run_apply(sh_path).await {
        Ok(_) => {
            sh_path.del("BAK");
            Ok(())
        }
        Err(err) => {
            tracing::error!("update_intercept_bridging command failed: {err:#}");

            // If the config apply failed, we won't be using it, so move it out
            // of the way to an .error file for others to enjoy (while attempting
            // to remove any previous .error file in the process).
            let path_error = sh_path.with_ext("error");
            if path_error.exists()
                && let Err(e) = fs::remove_file(path_error.clone())
            {
                tracing::warn!(
                    "Failed to remove previous error file ({}): {e}",
                    path_error.display()
                );
            }

            if let Err(err) = fs::rename(sh_path, &path_error) {
                eyre::bail!(
                    "rename {sh_path} to {} on error: {err:#}",
                    path_error.display()
                );
            }
            // .. and copy the old one back.
            // This also ensures that we retry writing the config on subsequent runs.
            let path_bak = sh_path.backup();
            if path_bak.exists()
                && let Err(err) = fs::rename(&path_bak, sh_path)
            {
                eyre::bail!(
                    "rename {} to {sh_path}, reverting on error: {err:#}",
                    path_bak.display(),
                );
            }

            Err(err)
        }
    }
}

// Apply the commands
pub async fn run_apply(sh_path: &super::FPath) -> eyre::Result<()> {
    let mut cmd = tokio::process::Command::new("bash");
    cmd.arg(sh_path.to_string()).kill_on_drop(true);
    let cmd_str = super::pretty_cmd(cmd.as_std());
    tracing::debug!("running intercept bridging commands: {cmd_str}");

    let out = tokio::time::timeout(std::time::Duration::from_secs(3), cmd.output())
        .await
        .wrap_err("Timeout")?
        .wrap_err("Error running command")?;

    if !out.status.success() {
        tracing::error!(
            " STDOUT {cmd_str}: {}",
            String::from_utf8_lossy(&out.stdout)
        );
        tracing::error!(
            " STDERR {cmd_str}: {}",
            String::from_utf8_lossy(&out.stderr)
        );

        let path_error = sh_path.with_ext("error");
        if let Err(err) = fs::rename(sh_path, &path_error) {
            eyre::bail!(
                "rename {sh_path} to {} on error: {err:#}",
                path_error.display()
            );
        }
    }

    Ok(())
}
