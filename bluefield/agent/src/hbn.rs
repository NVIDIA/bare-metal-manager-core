/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2023 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */

use std::process::Command;

use serde::Deserialize;
use tracing::debug;

pub fn get_hbn_container_id() -> eyre::Result<String> {
    let mut crictl = Command::new("crictl");
    let cmd = crictl.args(["ps", "--name=doca-hbn", "-o=json"]);
    let out = cmd.output()?;
    if !out.status.success() {
        debug!(
            "STDERR {}: {}",
            super::pretty_cmd(cmd),
            String::from_utf8_lossy(&out.stderr)
        );
        return Err(eyre::eyre!(
            "{} for cmd '{}'",
            out.status,
            super::pretty_cmd(cmd)
        ));
    }

    parse_container_id(&String::from_utf8_lossy(&out.stdout))
}

fn parse_container_id(json: &str) -> eyre::Result<String> {
    let o: CrictlOut = serde_json::from_str(json)?;
    if o.containers.is_empty() {
        return Err(eyre::eyre!(
            "crictl JSON output has empty 'containers' array. Is doca-hbn running?"
        ));
    }
    Ok(o.containers[0].id.clone())
}

#[derive(Deserialize, Debug)]
struct CrictlOut {
    containers: Vec<Container>,
}

#[derive(Deserialize, Debug)]
struct Container {
    id: String,
}

#[cfg(test)]
mod tests {
    use super::parse_container_id;
    const CRICTL_OUT: &str = r#"
{
  "containers": [
    {
      "id": "f11d4746b230d51598bac048331072597a87303fede8c1812e01612c496bbc43",
      "podSandboxId": "b5703f93d448f305b391c2583384b7d1a4e2266c35d12b0e0f2f01fe5083f93d",
      "metadata": {
        "name": "doca-hbn",
        "attempt": 0
      },
      "image": {
        "image": "sha256:05f1047133f9852bd739590fa53071cc6f6eb7cce0a695ce981ddba81317c368",
        "annotations": {
        }
      },
      "imageRef": "sha256:05f1047133f9852bd739590fa53071cc6f6eb7cce0a695ce981ddba81317c368",
      "state": "CONTAINER_RUNNING",
      "createdAt": "1678127057518777146",
      "labels": {
        "io.kubernetes.container.name": "doca-hbn",
        "io.kubernetes.pod.name": "doca-hbn-service-idaho-hamper.forge.local",
        "io.kubernetes.pod.namespace": "default",
        "io.kubernetes.pod.uid": "949491dc6d16952d446a7d0e80da5b18"
      },
      "annotations": {
        "io.kubernetes.container.hash": "ee4ee15b",
        "io.kubernetes.container.restartCount": "0",
        "io.kubernetes.container.terminationMessagePath": "/dev/termination-log",
        "io.kubernetes.container.terminationMessagePolicy": "File",
        "io.kubernetes.pod.terminationGracePeriod": "30"
      }
    }
  ]
}
"#;

    #[test]
    fn test_parse_container_id() -> eyre::Result<()> {
        assert_eq!(
            parse_container_id(CRICTL_OUT)?,
            "f11d4746b230d51598bac048331072597a87303fede8c1812e01612c496bbc43"
        );
        Ok(())
    }
}
