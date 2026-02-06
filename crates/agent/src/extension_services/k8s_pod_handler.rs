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
use std::collections::{HashMap, HashSet};
use std::fmt::Write;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};

use ::rpc::forge as rpc;
use async_trait::async_trait;
use eyre::{Result, WrapErr};
use serde_json::Value as Json;
use serde_yaml::Value;
use tokio::fs;
use tokio::io::AsyncWriteExt;
use tokio::process::Command as TokioCommand;
use tracing;

use super::service_handler::{
    CredentialType, ExtensionServiceHandler, ServiceConfig, UsernamePassword,
};
use crate::containerd::container;
use crate::extension_services::dpu_extension_service_observability;

// For writing the pod spec to the kubelet managed directory
const KUBERNETES_POD_DIR: &str = "/etc/kubelet.d";
const KUBERNETES_POD_DIR_TMP: &str = "/etc/kubelet.d.tmp";
const KUBERNETES_POD_FILENAME_PREFIX: &str = "extservice";

// For identifying the pod in crictl
const KUBERNETES_POD_LABEL_ID: &str = "extservice-id";
const KUBERNETES_POD_LABEL_VER: &str = "extservice-version";

// Path for configuring the credential provider
const KUBELET_POD_IMAGE_CRED_DIR: &str = "/var/lib/kubelet/image-cred";
const KUBELET_POD_IMAGE_CRED_CONFIG_FILE: &str = "/var/lib/kubelet/image-cred/config.yaml";
const KUBELET_POD_IMAGE_CRED_PROVIDER_FILE: &str = "/var/lib/kubelet/image-cred/bin/cred-provider";
const KUBELET_SYSTEMD_OVERRIDE_DIR: &str = "/etc/systemd/system/kubelet@mgmt.service.d";
const KUBELET_SYSTEMD_OVERRIDE_FILE: &str =
    "/etc/systemd/system/kubelet@mgmt.service.d/override.conf";

// Path for configuring the socks proxy for containerd
const CONTAINERD_OVERRIDE_DIR: &str = "/etc/systemd/system/containerd@mgmt.service.d";
const CONTAINERD_PROXY_FILE: &str = "/etc/systemd/system/containerd@mgmt.service.d/http_proxy.conf";

// Path for extension services OTEL config files
const OTEL_CONTRIB_DPU_EXT_PATH: &str = "/etc/otelcol-contrib/config-fragments";
const MAX_OBSERVABILITY_CONFIG_PER_SERVICE: usize = 20;

/// Handler for KUBERNETES_POD extension services
#[derive(Default)]
pub struct KubernetesPodServicesHandler {
    /// Map of (service_id, version) to error message if deployment/teardown hit issues
    pub service_errors: HashMap<(String, u64), String>,

    /// Whether the credential provider has been initialized for current creds.
    pub cred_reconciled: bool,
    /// Current registry credential set applied to kubelet.
    pub current_creds: HashMap<String, UsernamePassword>,

    /// Whether containerd SOCKS proxy has been configured.
    pub socks_proxy_configured: bool,
}

impl KubernetesPodServicesHandler {
    /// Generate the pod spec file path for a service
    fn get_pod_spec_path(&self, service_id: &str, service_version: u64) -> PathBuf {
        let filename = format!(
            "{}_{}_{}.yaml",
            KUBERNETES_POD_FILENAME_PREFIX, service_id, service_version
        );
        PathBuf::from(KUBERNETES_POD_DIR).join(filename)
    }

    /// Generate the temporary pod spec file path for a service
    fn get_temp_pod_spec_path(&self, service_id: &str, service_version: u64) -> PathBuf {
        let filename = format!(
            "{}_{}_{}.yaml",
            KUBERNETES_POD_FILENAME_PREFIX, service_id, service_version
        );
        PathBuf::from(KUBERNETES_POD_DIR_TMP).join(filename)
    }

    /// Parse the service ID and version from the pod spec file name
    fn get_service_id_and_version_from_filename(filename: &str) -> Option<(uuid::Uuid, u64)> {
        // Strip any suffix
        let stem = match filename.rfind('.') {
            Some(dot) => &filename[..dot],
            None => filename,
        };

        // Strip the prefix
        let expected_lead = format!("{KUBERNETES_POD_FILENAME_PREFIX}_");
        let rest = stem.strip_prefix(&expected_lead)?;

        // Split the rest into ID and version
        let (id_str, ver_str) = rest.split_once('_')?;
        let version = ver_str.parse::<u64>().ok()?;

        let service_id = uuid::Uuid::parse_str(id_str).ok()?; // return None if not a UUID

        Some((service_id, version))
    }

    /// Parse the state of a container from crictl output.
    fn parse_state(&self, state: container::ContainerState) -> &'static str {
        match state {
            container::ContainerState::Running => "RUNNING",
            container::ContainerState::Exited => "EXITED",
            container::ContainerState::Unknown => "UNKNOWN",
            container::ContainerState::Created => "CREATED",
        }
    }

    /// Parse the pod state from the crictl output
    fn parse_pod_state(&self, state: &str) -> &'static str {
        match state.to_uppercase().as_str() {
            "SANDBOX_READY" | "READY" => "SANDBOX_READY",
            "SANDBOX_NOTREADY" | "NOTREADY" => "SANDBOX_NOTREADY",
            _ => "UNKNOWN",
        }
    }

    // Injects discovery labels into a pod spec YAML string.
    /// We intentionally avoid serializing back with `serde_yaml` because reformatting can
    /// strip quotes/comments; kubelet may fail if important quoting is lost.
    fn inject_labels(yaml: &str, service_id: &str, version: u64) -> Result<String> {
        let mut spec = serde_yaml::from_str::<Value>(yaml)?;

        let _ = spec
            .get_mut("metadata")
            .and_then(Value::as_mapping_mut)
            .ok_or_else(|| eyre::eyre!("Pod spec missing metadata"))?;

        let id = format!("    {}: \"{}\"\n", KUBERNETES_POD_LABEL_ID, service_id);
        let ver = format!("    {}: \"{}\"\n", KUBERNETES_POD_LABEL_VER, version);

        // If already has `labels:`, we insert the id right after it
        if let Some(pos) = yaml.find("\n  labels:\n") {
            let insert_at = pos + "\n  labels:\n".len();
            let mut out = String::with_capacity(yaml.len() + id.len() + ver.len());
            out.push_str(&yaml[..insert_at]);
            out.push_str(&id);
            out.push_str(&ver);
            out.push_str(&yaml[insert_at..]);
            return Ok(out);
        }

        // If no `labels:`, we add a labels block right after `metadata:`, which is guaranteed to
        // exist as it's validated during extension service creation.
        if let Some(pos) = yaml.find("\nmetadata:\n") {
            let insert_at = pos + "\nmetadata:\n".len();
            let mut out = String::with_capacity(yaml.len() + id.len() + ver.len() + 10);
            out.push_str(&yaml[..insert_at]);
            out.push_str("  labels:\n");
            out.push_str(&id);
            out.push_str(&ver);
            out.push_str(&yaml[insert_at..]);
            return Ok(out);
        }

        Err(eyre::eyre!(
            "Failed to inject labels: metadata field not found"
        ))
    }

    /// Restart a systemd service and apply changes to the service configuration.
    async fn systemctl_restart(&self, service: &str) -> Result<()> {
        tracing::debug!(
            "systemctl daemon-reload and restart {} to apply changes",
            service
        );

        // Run systemctl daemon-reload
        let daemon_reload = TokioCommand::new("systemctl")
            .args(["daemon-reload"])
            .output()
            .await
            .wrap_err("Failed to run systemctl daemon-reload")?;

        if !daemon_reload.status.success() {
            let stderr = String::from_utf8_lossy(&daemon_reload.stderr);
            tracing::warn!("systemctl daemon-reload failed: {}", stderr);
        }

        // Run systemctl restart <service>
        let restart = TokioCommand::new("systemctl")
            .args(["restart", service])
            .output()
            .await
            .wrap_err(format!("Failed to restart {}", service))?;

        if !restart.status.success() {
            let stderr = String::from_utf8_lossy(&restart.stderr);
            return Err(eyre::eyre!("Failed to restart {}: {}", service, stderr));
        }

        tracing::debug!("Successfully restarted {}", service);

        Ok(())
    }

    /// Execute `crictl` and parse JSON output.
    async fn crictl_output(args: &[&str]) -> Result<Json> {
        let output = TokioCommand::new("crictl")
            .args(args)
            .output()
            .await
            .wrap_err("Failed to get crictl output")?;

        if !output.status.success() {
            let stderr =
                String::from_utf8(output.stderr).wrap_err("Failed to parse crictl output")?;
            return Err(eyre::eyre!("Failed to get crictl output: {}", stderr));
        }
        let stdout = String::from_utf8(output.stdout).wrap_err("Failed to parse crictl output")?;
        let json = serde_json::from_str(&stdout).wrap_err("Failed to parse crictl output")?;

        Ok(json)
    }

    /// Atomic write pod spec to kubelet directory.
    async fn write_pod_spec(&self, service: &ServiceConfig) -> eyre::Result<()> {
        let pod_spec_path =
            self.get_pod_spec_path(&service.id.to_string(), service.version.version_nr());
        let tmp_path =
            self.get_temp_pod_spec_path(&service.id.to_string(), service.version.version_nr());

        std::fs::create_dir_all(Path::new(KUBERNETES_POD_DIR))
            .wrap_err("Failed to create pod spec directory")?;

        std::fs::create_dir_all(Path::new(KUBERNETES_POD_DIR_TMP))
            .wrap_err("Failed to create tmp pod spec directory")?;

        // We need to inject labels to help identify pod in crictl
        let labeled_yaml = Self::inject_labels(
            &service.data,
            &service.id.to_string(),
            service.version.version_nr(),
        )?;

        // Create the tmp file and write the pod spec YAML to it
        let mut tmp_file = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&tmp_path)
            .await
            .wrap_err_with(|| format!("Failed to create tmp file {}", tmp_path.display()))?;

        tmp_file
            .write_all(labeled_yaml.as_bytes())
            .await
            .wrap_err("Failed to write pod spec data")?;

        // Ensure data is written to disk
        tmp_file
            .sync_all()
            .await
            .wrap_err("Failed to sync pod spec data to disk")?;

        drop(tmp_file);

        // Atomically rename the tmp file to the pod spec path
        fs::rename(&tmp_path, &pod_spec_path)
            .await
            .wrap_err_with(|| {
                format!(
                    "Failed to rename {} to {}",
                    tmp_path.display(),
                    pod_spec_path.display()
                )
            })?;

        tracing::debug!(
            "Pod spec for service {} V{} written successfully at {}",
            service.id,
            service.version,
            pod_spec_path.display()
        );

        Ok(())
    }

    /// Remove pod spec from kubelet directory
    async fn remove_pod_spec(&self, service_id: &str, service_version: u64) -> eyre::Result<()> {
        let pod_spec_path = self.get_pod_spec_path(service_id, service_version);

        match fs::remove_file(&pod_spec_path).await {
            Ok(()) => {
                tracing::debug!(
                    "Pod spec for service {} V{} removed successfully at {}",
                    service_id,
                    service_version,
                    pod_spec_path.display()
                );
            }
            Err(e) if e.kind() == ErrorKind::NotFound => {
                tracing::debug!(
                    "Pod spec for service {} V{} already gone (nothing to remove) at {}",
                    service_id,
                    service_version,
                    pod_spec_path.display()
                );
            }
            Err(e) => {
                return Err(e).wrap_err_with(|| {
                    format!("Failed to remove pod spec {}", pod_spec_path.display())
                });
            }
        }

        Ok(())
    }

    /// Find the pod ID for the given service using the labels we injected into the pod spec.
    ///
    /// - Returns `Ok(None)` if no pod matches the service labels.
    /// - Returns `Ok(Some(pod_id))` if exactly one pod matches.
    /// - Returns an error if multiple pods match or if the crictl output is invalid.
    async fn find_pod_id(&self, service: &ServiceConfig) -> eyre::Result<Option<String>> {
        let args = &[
            "pods",
            "-o",
            "json",
            "--label",
            &format!("{KUBERNETES_POD_LABEL_ID}={}", service.id),
            "--label",
            &format!(
                "{KUBERNETES_POD_LABEL_VER}={}",
                service.version.version_nr()
            ),
        ];

        let json = Self::crictl_output(args)
            .await
            .wrap_err("Failed to find run crictl pods")?;

        let items = json
            .get("items")
            .and_then(|v| v.as_array())
            .ok_or_else(|| eyre::eyre!("crictl output missing items[]"))?;

        match items.len() {
            0 => Ok(None),
            1 => {
                let id = items[0]
                    .get("id")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| eyre::eyre!("pod object missing string `id` field"))?;
                Ok(Some(id.to_owned()))
            }
            n => Err(eyre::eyre!(
                "multiple pods found for service id={} version={} ({} matches, should be unique)",
                service.id,
                service.version,
                n
            )),
        }
    }

    /// Compute an overall deployment status from per-container states and intent.
    ///
    /// Inputs:
    /// - `statuses`: normalized container states (e.g. "RUNNING", "EXITED", "CREATED", "UNKNOWN").
    /// - `expected_deploy`: whether we expect the service to be up (deployed) now.
    ///
    /// Rules:
    /// - If no containers:
    ///     - expected -> PENDING
    ///     - not expected -> TERMINATED
    /// - When expected to be deployed:
    ///     - all RUNNING -> RUNNING
    ///     - any EXITED -> ERROR
    ///     - any CREATED or UNKNOWN -> PENDING
    ///     - otherwise -> PENDING
    /// - When NOT expected to be deployed (we expect it to be gone):
    ///     - any RUNNING or CREATED or UNKNOWN -> TERMINATING
    ///     - all EXITED -> TERMINATED
    ///     - otherwise -> TERMINATED
    fn aggregate_status(
        &self,
        pod_status: &str,
        statuses: &[String],
        expected_deploy: bool,
    ) -> rpc::DpuExtensionServiceDeploymentStatus {
        if statuses.is_empty() {
            return if expected_deploy {
                rpc::DpuExtensionServiceDeploymentStatus::DpuExtensionServicePending
            } else if pod_status == "SANDBOX_NOTREADY" {
                rpc::DpuExtensionServiceDeploymentStatus::DpuExtensionServiceTerminating
            } else {
                rpc::DpuExtensionServiceDeploymentStatus::DpuExtensionServiceTerminated
            };
        }

        let all_running = statuses.iter().all(|s| s == "RUNNING");
        let all_exited = statuses.iter().all(|s| s == "EXITED");

        let any_running = statuses.iter().any(|s| s == "RUNNING");
        let any_exited = statuses.iter().any(|s| s == "EXITED");
        let any_created = statuses.iter().any(|s| s == "CREATED");
        let any_unknown = statuses.iter().any(|s| s == "UNKNOWN");

        if expected_deploy {
            if all_running {
                return rpc::DpuExtensionServiceDeploymentStatus::DpuExtensionServiceRunning;
            }
            if any_exited {
                return rpc::DpuExtensionServiceDeploymentStatus::DpuExtensionServiceError;
            }
            if any_created {
                return rpc::DpuExtensionServiceDeploymentStatus::DpuExtensionServicePending;
            }
            if any_unknown {
                return rpc::DpuExtensionServiceDeploymentStatus::DpuExtensionServiceUnknown;
            }
            rpc::DpuExtensionServiceDeploymentStatus::DpuExtensionServicePending
        } else {
            if any_unknown {
                return rpc::DpuExtensionServiceDeploymentStatus::DpuExtensionServiceUnknown;
            }
            // We expect it gone
            if any_running || any_created {
                return rpc::DpuExtensionServiceDeploymentStatus::DpuExtensionServiceTerminating;
            }
            if statuses.is_empty() || all_exited {
                return rpc::DpuExtensionServiceDeploymentStatus::DpuExtensionServiceTerminated;
            }
            rpc::DpuExtensionServiceDeploymentStatus::DpuExtensionServiceTerminated
        }
    }

    /// Inspect the pod sandbox status from the crictl output
    async fn get_pod_sandbox_status(&self, pod_id: &str) -> Result<String> {
        let pod = Self::crictl_output(&["inspectp", pod_id])
            .await
            .wrap_err("Failed to inspect pod sandbox")?;

        // Assume the pod state is in nested field status.state
        let pod_state = pod
            .get("status")
            .and_then(|s| s.get("state"))
            .and_then(|v| v.as_str())
            // Fallback for older outputs where "status" is already a string
            .or_else(|| pod.get("status").and_then(|v| v.as_str()))
            .unwrap_or("UNKNOWN");

        Ok(self.parse_pod_state(pod_state).to_string())
    }

    /// Determine the overall status of the pod from crictl
    async fn get_pod_status(
        &self,
        service: &ServiceConfig,
    ) -> Result<rpc::DpuExtensionServiceStatusObservation> {
        let expected_deploy = service.removed.is_none();

        let _pod_spec_path =
            self.get_pod_spec_path(&service.id.to_string(), service.version.version_nr());

        // Find the pod ID for the service using the label we injected into the pod spec
        let pod_id = match self.find_pod_id(service).await {
            Ok(Some(pod_id)) => pod_id,
            Ok(None) => {
                let state_enum = match expected_deploy {
                    true => rpc::DpuExtensionServiceDeploymentStatus::DpuExtensionServicePending,
                    false => {
                        rpc::DpuExtensionServiceDeploymentStatus::DpuExtensionServiceTerminated
                    }
                };
                return Ok(rpc::DpuExtensionServiceStatusObservation {
                    service_id: service.id.to_string(),
                    service_type: service.service_type as i32,
                    service_name: service.id.to_string(),
                    version: service.version.to_string(),
                    removed: service.removed.clone(),
                    state: state_enum as i32,
                    components: Vec::new(),
                    message: "No pod sandbox found".to_string(),
                });
            }
            Err(e) => {
                return Ok(rpc::DpuExtensionServiceStatusObservation {
                    service_id: service.id.to_string(),
                    service_type: service.service_type as i32,
                    service_name: service.id.to_string(),
                    version: service.version.to_string(),
                    removed: service.removed.clone(),
                    state: rpc::DpuExtensionServiceDeploymentStatus::DpuExtensionServiceError
                        as i32,
                    components: Vec::new(),
                    message: format!("Failed to find pod ID: {}", e),
                });
            }
        };

        // Check pod overall status
        let pod_state = match self.get_pod_sandbox_status(&pod_id).await {
            Ok(pod_state) => pod_state,
            Err(e) => {
                return Ok(rpc::DpuExtensionServiceStatusObservation {
                    service_id: service.id.to_string(),
                    service_type: service.service_type as i32,
                    service_name: service.id.to_string(),
                    version: service.version.to_string(),
                    removed: service.removed.clone(),
                    state: rpc::DpuExtensionServiceDeploymentStatus::DpuExtensionServiceError
                        as i32,
                    components: Vec::new(),
                    message: format!("Failed to inspect pod status pod {}: {}", pod_id, e),
                });
            }
        };

        // Get the images
        let images = container::Images::list().await.ok();

        // Get the containers for the pod
        let container_list = container::Containers::list_pod(&pod_id).await?;
        let containers = container_list.containers;
        let mut components = Vec::with_capacity(containers.len());
        let mut container_statuses = Vec::with_capacity(containers.len());
        for container in containers {
            let container_name = container.metadata.name;

            let container_state = self.parse_state(container.state).to_string();
            container_statuses.push(container_state.to_string());

            let image_id = container.image.id;
            let (image_url, image_version) = match images.as_ref() {
                Some(images) => {
                    let images_clone = images.clone();
                    match images_clone.find_by_id(&image_id) {
                        Ok(image) => match image.names.len() {
                            0 => ("".to_string(), "".to_string()),
                            _ => {
                                let name = image.names.first().unwrap();
                                let url = format!("{}/{}", name.repository, name.name);
                                (url, name.version.to_string())
                            }
                        },
                        Err(_) => ("".to_string(), "".to_string()),
                    }
                }
                None => ("".to_string(), "".to_string()),
            };

            components.push(rpc::DpuExtensionServiceComponent {
                name: container_name.to_string(),
                version: image_version,
                url: image_url,
                status: container_state.to_string(),
            });
        }

        // Aggregate overall state
        let state_enum = self.aggregate_status(&pod_state, &container_statuses, expected_deploy);

        let err_message = match self
            .service_errors
            .get(&(service.id.to_string(), service.version.version_nr()))
        {
            Some(e) => e.to_string(),
            None => format!("pod state: {}", pod_state),
        };

        Ok(rpc::DpuExtensionServiceStatusObservation {
            service_id: service.id.to_string(),
            service_type: service.service_type as i32,
            service_name: service.id.to_string(),
            version: service.version.to_string(),
            removed: service.removed.clone(),
            state: state_enum as i32,
            components,
            message: err_message,
        })
    }

    /// Generate credential provider config JSON.
    /// We expect the registry_url to be the prefix of the image,
    /// see https://kubernetes.io/docs/tasks/administer-cluster/kubelet-credential-provider/
    /// e.g. if the extension service wants to configure credentials for the images
    /// "nvcr.io/nv-ngn/sdn/ovn-c-arm64" and "nvcr.io/nv-ngn/sdn/ovnkube", then the registry_url
    ///  should be "nvcr.io/nv-ngn/sdn"
    fn generate_credential_provider_config(
        &self,
        credential_list: &HashMap<String, UsernamePassword>,
    ) -> Result<String> {
        use serde_json::json;
        // Extract registry prefixes for matchImages
        let match_images: Vec<String> = credential_list
            .keys()
            .map(|url| url.trim_end_matches('/').to_string())
            .collect();

        let config = json!({
            "apiVersion": "kubelet.config.k8s.io/v1",
            "kind": "CredentialProviderConfig",
            "providers": [{
                "name": "cred-provider",
                "apiVersion": "credentialprovider.kubelet.k8s.io/v1",
                "matchImages": match_images,
                "defaultCacheDuration": "10m"
            }]
        });

        Ok(serde_json::to_string_pretty(&config)?)
    }

    /// Generate credential provider bash script that can be used by kubelet to dynamically
    /// retrieve credentials for container image registries.
    /// See https://kubernetes.io/docs/tasks/administer-cluster/kubelet-credential-provider/
    /// for more details.
    fn generate_credential_provider_script(
        &self,
        credential_list: &HashMap<String, UsernamePassword>,
    ) -> Result<String> {
        let mut keys: Vec<_> = credential_list.keys().collect();

        if keys.is_empty() {
            return Err(eyre::eyre!(
                "No credentials provided. Should never configure a credential provider with no credentials."
            ));
        }

        keys.sort();

        let mut tsv = String::new();
        for k in keys {
            let prefix = k.trim_end_matches('/'); // tolerate trailing slash in config
            let up = &credential_list[k];
            let _ = writeln!(&mut tsv, "{}\t{}\t{}", prefix, up.username, up.password);
        }

        let script = format!(
            r#"#!/bin/bash
set -euo pipefail

LOG="/var/lib/kubelet/image-cred/cred-provider.log"

# TSV: PREFIX<TAB>USERNAME<TAB>PASSWORD
# safest: cat + heredoc (always succeeds)
CREDENTIALS="$(
  cat <<'CREDS'
{tsv}CREDS
)"

# Read kubelet request from stdin
REQ="$(cat || true)"

# Optional debug logging (best-effort)
{{ printf '%s | called\n' "$(date -Is)"; printf '%s\n\n' "$REQ"; }} >> "$LOG" || true

IMAGE="$(printf '%s' "$REQ" | sed -n 's/.*"image"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -n1)"

USER=""; PASS=""; HOST=""

# Select first matching prefix; derive registry host from prefix
while IFS=$'\t' read -r PREFIX U P; do
  [[ -z "${{PREFIX:-}}" ]] && continue
  if [[ "$IMAGE" == "$PREFIX"* ]]; then
    USER="$U"
    PASS="$P"
    HOST="${{PREFIX%%/*}}"   # host is the first path component of the prefix
    break
  fi
done <<< "$CREDENTIALS"

# No match: return empty auth
if [[ -z "$USER" ]]; then
  cat <<'JSON'
{{
  "apiVersion": "credentialprovider.kubelet.k8s.io/v1",
  "kind": "CredentialProviderResponse",
  "cacheKeyType": "Image",
  "cacheDuration": "1h",
  "auth": {{}}
}}
JSON
  exit 0
fi

# Emit creds for the matched host
cat <<JSON
{{
  "apiVersion": "credentialprovider.kubelet.k8s.io/v1",
  "kind": "CredentialProviderResponse",
  "cacheKeyType": "Image",
  "cacheDuration": "1h",
  "auth": {{
    "$HOST": {{
      "username": "$USER",
      "password": "$PASS"
    }}
  }}
}}
JSON
"#,
            tsv = tsv
        );

        Ok(script)
    }

    /// Write kubelet systemd override configuration to enable image credential provider
    fn write_kubelet_override_conf(&self) -> Result<()> {
        // Create systemd override directory if it doesn't exist
        std::fs::create_dir_all(Path::new(KUBELET_SYSTEMD_OVERRIDE_DIR))
            .wrap_err("Failed to create kubelet systemd override directory")?;

        // Check if override file already exists and has correct content
        let override_content = format!(
            "[Service]\nEnvironment=\"KUBELET_CONFIG_ARGS=--config=/var/lib/kubelet/config.yaml \
            --image-credential-provider-config={} \
            --image-credential-provider-bin-dir={} --v=6\"\n",
            KUBELET_POD_IMAGE_CRED_CONFIG_FILE,
            Path::new(KUBELET_POD_IMAGE_CRED_PROVIDER_FILE)
                .parent()
                .unwrap()
                .display()
        );

        // Read existing content if file exists
        let needs_update = match std::fs::read_to_string(KUBELET_SYSTEMD_OVERRIDE_FILE) {
            Ok(existing) => existing != override_content,
            Err(e) if e.kind() == ErrorKind::NotFound => true,
            Err(e) => {
                return Err(eyre::eyre!(
                    "Failed to read existing kubelet override file: {}",
                    e
                ));
            }
        };

        if needs_update {
            std::fs::write(KUBELET_SYSTEMD_OVERRIDE_FILE, override_content)
                .wrap_err("Failed to write kubelet systemd override file")?;
            tracing::debug!(
                "Written kubelet systemd override to {}",
                KUBELET_SYSTEMD_OVERRIDE_FILE
            );
        } else {
            tracing::debug!(
                "Kubelet systemd override already up to date at {}",
                KUBELET_SYSTEMD_OVERRIDE_FILE
            );
        }

        Ok(())
    }

    /// Configure containerd to use a SOCKS proxy for pulling container images.
    async fn setup_socks_proxy(&mut self) -> Result<()> {
        if self.socks_proxy_configured {
            return Ok(());
        }

        let socks_proxy_config = r#"[Service]
Environment="HTTP_PROXY=socks5://socks.forge:1888"
Environment="HTTPS_PROXY=socks5://socks.forge:1888"
Environment="NO_PROXY=127.0.0.1,localhost,.svc,.svc.cluster.local"
"#;

        // Create containerd override directory if it doesn't exist
        let containerd_override_dir = Path::new(CONTAINERD_OVERRIDE_DIR);
        std::fs::create_dir_all(containerd_override_dir)
            .wrap_err("Failed to create containerd override directory")?;

        // Write containerd proxy config
        std::fs::write(CONTAINERD_PROXY_FILE, socks_proxy_config)
            .wrap_err("Failed to write containerd proxy file")?;

        // Restart containerd@mgmt.service to apply changes
        self.systemctl_restart("containerd@mgmt.service").await?;

        self.socks_proxy_configured = true;

        Ok(())
    }

    /// Reconcile the credential provider configuration to reflect the active services.
    ///
    /// - If credentials are unchanged since last reconcile, this is a no-op.
    /// - If the desired set is empty, tear down the provider (kubelet rejects empty match lists).
    /// - Otherwise, write config + script and restart kubelet.
    async fn reconcile_pod_specs(&mut self, new_active: &[ServiceConfig]) -> Result<()> {
        // Set of (service ID, version) tuples that are currently active, i.e. present in the kubelet directory
        let mut current_active: HashSet<(uuid::Uuid, u64)> = HashSet::new();

        // List the /etc/kubelet.d directory and get list of current pod specs in it
        let kubelet_dir = Path::new(KUBERNETES_POD_DIR);
        std::fs::create_dir_all(kubelet_dir).wrap_err_with(|| {
            format!(
                "Failed to create kubelet directory at {}",
                kubelet_dir.display()
            )
        })?;

        let dir_iter = std::fs::read_dir(kubelet_dir).wrap_err_with(|| {
            format!("Failed to read kubelet directory {}", kubelet_dir.display())
        })?;

        for entry in dir_iter {
            let entry = match entry {
                Ok(entry) => entry,
                Err(e) => {
                    tracing::warn!(
                        error = %e,
                        "Failed to read kubelet directory entry"
                    );
                    continue;
                }
            };

            let path = entry.path();
            if !path.is_file() {
                continue;
            }

            let file_name = match path.file_name() {
                Some(name) => name.to_string_lossy().into_owned(),
                None => {
                    tracing::warn!(
                        path = %path.display(),
                        "Ignoring file in kubelet directory: unable to extract filename from path"
                    );
                    continue;
                }
            };

            if let Some((service_id, version)) =
                Self::get_service_id_and_version_from_filename(&file_name)
            {
                current_active.insert((service_id, version));
            } else {
                // This is not a pod spec file managed by extension service, ignore it
                continue;
            }
        }

        // Compare the current active set with the new active set
        for service in new_active {
            if !current_active.contains(&(service.id, service.version.version_nr())) {
                // Found new service, write pod spec
                match self.write_pod_spec(service).await {
                    Ok(_) => (),
                    Err(e) => {
                        self.service_errors.insert(
                            (service.id.to_string(), service.version.version_nr()),
                            e.to_string(),
                        );
                    }
                }
            }
        }
        for (service_id, version) in current_active {
            if !new_active
                .iter()
                .any(|s| s.id == service_id && s.version.version_nr() == version)
            {
                // Service is not active, remove it
                match self.remove_pod_spec(&service_id.to_string(), version).await {
                    Ok(_) => (),
                    Err(e) => {
                        self.service_errors
                            .insert((service_id.to_string(), version), e.to_string());
                    }
                }
            }
        }

        Ok(())
    }

    // Reconcile the credential provider to contain the credentials for the new services' images.
    // If the credentials are changed, re-configure the credential provider and restart the
    // kubelet to pick up the new credentials.
    // If no credentials are provided, tear down the credential provider and restart the kubelet.
    async fn reconcile_credential_provider(&mut self, services: &[ServiceConfig]) -> Result<()> {
        let mut credential_list = HashMap::new();

        // Get the list of credentials for the new active services
        for service in services {
            if let Some(credential) = &service.credential {
                match credential.credential_type.clone() {
                    CredentialType::UsernamePassword(up) => {
                        credential_list.insert(credential.registry_url.clone(), up);
                    }
                }
            }
        }

        if self.cred_reconciled && self.current_creds == credential_list {
            tracing::debug!("Credential provider already configured");
            return Ok(());
        }

        if credential_list.is_empty() {
            // We need to tear down the credential provider if no credentials are provided because
            // kubelet will not allow credential provider config with empty image-match list
            tracing::debug!("Tearing down credential provider");

            // Best-effort deletes (treat NotFound as success)
            for path in [
                KUBELET_POD_IMAGE_CRED_PROVIDER_FILE,
                KUBELET_POD_IMAGE_CRED_CONFIG_FILE,
                KUBELET_SYSTEMD_OVERRIDE_FILE,
            ] {
                match std::fs::remove_file(path) {
                    Ok(_) => tracing::debug!("Removed {}", path),
                    Err(e) if e.kind() == ErrorKind::NotFound => {
                        tracing::debug!("{} already absent", path);
                    }
                    Err(e) => return Err(eyre::eyre!("Failed to remove {}: {}", path, e)),
                }
            }
        } else {
            tracing::debug!(
                "Configuring credential provider for {} registries or organizations",
                credential_list.len()
            );

            // Create credential directory structure
            let image_cred_dir = Path::new(KUBELET_POD_IMAGE_CRED_DIR);
            std::fs::create_dir_all(image_cred_dir)
                .wrap_err("Failed to create image credential directory")?;

            let image_cred_bin_dir = image_cred_dir.join("bin");
            std::fs::create_dir_all(&image_cred_bin_dir)
                .wrap_err("Failed to create image credential bin directory")?;

            // Generate credential provider config
            let config_content = self
                .generate_credential_provider_config(&credential_list)
                .wrap_err("Failed to generate credential provider config")?;

            std::fs::write(KUBELET_POD_IMAGE_CRED_CONFIG_FILE, config_content)
                .wrap_err("Failed to write credential provider config")?;

            tracing::debug!(
                "Written credential provider config to {}",
                KUBELET_POD_IMAGE_CRED_CONFIG_FILE
            );

            // Write kubelet systemd override to configure image credential provider
            self.write_kubelet_override_conf()?;

            // Generate credential provider script
            let script_content = self.generate_credential_provider_script(&credential_list)?;
            std::fs::write(KUBELET_POD_IMAGE_CRED_PROVIDER_FILE, script_content)
                .wrap_err("Failed to write credential provider script")?;

            // Make script executable on Unix systems
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let mut perms =
                    std::fs::metadata(KUBELET_POD_IMAGE_CRED_PROVIDER_FILE)?.permissions();
                perms.set_mode(0o755);
                std::fs::set_permissions(KUBELET_POD_IMAGE_CRED_PROVIDER_FILE, perms)?;
            }

            tracing::debug!(
                "Written credential provider script to {}",
                KUBELET_POD_IMAGE_CRED_PROVIDER_FILE
            );
        }

        // Restart kubelet to pick up new credentials
        self.systemctl_restart("kubelet@mgmt.service").await?;

        self.cred_reconciled = true;
        self.current_creds = credential_list;

        Ok(())
    }

    // Reconcile the DPU OTEL metrics collection config based, adding/updating config
    // for new/existing services and removing config for inactive services.
    // If no config is provided for a service, any existing metrics config will be removed.
    async fn reconcile_observability(&mut self, services: &[ServiceConfig]) -> Result<()> {
        let mut changed = false;

        // Loop through the items in services.
        for service in services {
            let config_path =
                PathBuf::from(format!("{OTEL_CONTRIB_DPU_EXT_PATH}/{}.yaml", service.id));
            let tmp_path = config_path.with_extension("TMP");

            if let Some(observability) = service.observability.as_ref() {
                // Check if the service is marked removed or has no metrics config
                if service.removed.is_some() || observability.configs.is_empty() {
                    // Check if a config file exists
                    if std::fs::exists(config_path.clone())? {
                        // If so, flag that we're changing something and remove the file.
                        changed = true;
                        std::fs::remove_file(config_path)?;
                    }
                } else if observability.configs.len() > MAX_OBSERVABILITY_CONFIG_PER_SERVICE {
                    tracing::error!(
                        "number of observability configs for service `{}` exceeds the limit of {MAX_OBSERVABILITY_CONFIG_PER_SERVICE}",
                        service.id
                    );

                    // We protect against this case in the API layer, so this case,
                    // _should_ never be hit, but we need to do whatever we can to
                    // prevent user-config from blocking the rest of our DPU loop.
                    // Config count that exceeds our imposed limit isn't a systemic
                    // failure (nothing is wrong with the DPU), so we should log and
                    // remove the config.  The user will then need to fix their config
                    // to get their metrics again.
                    changed = true;
                    std::fs::remove_file(config_path)?;
                } else {
                    // If the service is active and has metrics config, loop through
                    // and generate a tmp config file.
                    let contents = dpu_extension_service_observability::build(
                        service.id,
                        service.name.to_owned(),
                        observability,
                    )?;

                    std::fs::write(&tmp_path, contents.clone())
                        .wrap_err_with(|| format!("fs::write {}", tmp_path.display()))?;

                    // If no config file already exists, move temp to active and mark changed.
                    if !std::fs::exists(config_path.clone())? {
                        std::fs::rename(tmp_path, config_path).wrap_err("rename")?;
                        changed = true;
                    } else {
                        // Read in the current config
                        let current = std::fs::read_to_string(config_path.clone())
                            .wrap_err("read current config")?;
                        // If there was no change, nothing to do so just clean-up.
                        if contents == current {
                            std::fs::remove_file(&tmp_path)
                                .wrap_err("remove temp metrics config")?;
                        } else {
                            // If there was a change, move tmp to current
                            std::fs::rename(tmp_path, config_path).wrap_err("rename")?;
                            changed = true;
                        }
                    }
                }
            } else {
                // Check if a config file exists
                if std::fs::exists(config_path.clone())? {
                    // If so, flag that we're changing something and remove the file.
                    changed = true;
                    std::fs::remove_file(config_path)?;
                }
            }
        }

        // If there were changes, restart the otel service.
        if changed {
            // We intentionally turn validation failure into a non-fatal
            // event and continue on to give users a strong signal (their
            // metrics break) in the event that they've crafted config
            // that passes the validation at our API layer but managed
            // to be rejected by otel.
            // The otel service wrapper itself will validate the combined
            // config (base + config fragments) and ignore all extension
            // config if validation fails.
            // We'll still get _our_ base metrics if the user submited bad
            // config, but the user will lose theirs until they fix their
            // config.
            if !dpu_extension_service_observability::validate().await? {
                tracing::error!("extension service observability configs failed validation")
            }

            self.systemctl_restart("otelcol-contrib.service").await?;
        }

        Ok(())
    }

    /// Update the services in the kubelet directory, then configure the credential provider to
    /// contain the credentials for the new services' images
    async fn update_services(&mut self, services: &[ServiceConfig]) -> Result<()> {
        // Clear any previous errors since we are starting a new update
        self.service_errors.clear();

        let active_services: Vec<ServiceConfig> = services
            .iter()
            .filter(|s| s.removed.is_none())
            .cloned()
            .collect();

        // Setup the socks proxy for pulling container images if it is not already configured
        self.setup_socks_proxy()
            .await
            .map_err(|e| eyre::eyre!("Failed to setup socks proxy: {}", e))?;

        // Reconcile the kubelet directory with the desired service spec files
        self.reconcile_pod_specs(&active_services)
            .await
            .map_err(|e| eyre::eyre!("Failed to reconcile pod specs: {}", e))?;

        // Reconcile the credential provider to contain the credentials for the new services' images
        self.reconcile_credential_provider(&active_services)
            .await
            .map_err(|e| eyre::eyre!("Failed to reconcile credential provider: {}", e))?;

        // Reconcile metrics collection config
        self.reconcile_observability(services)
            .await
            .map_err(|e| eyre::eyre!("Failed to reconcile metrics collection: {}", e))?;

        Ok(())
    }
}

#[async_trait]
impl ExtensionServiceHandler for KubernetesPodServicesHandler {
    /// Batch deployment using directory-based reconciliation
    /// This reconciles the /etc/kubelet.d directory with the desired services
    async fn update_active_services(&mut self, services: &[ServiceConfig]) -> Result<()> {
        if let Err(e) = self.update_services(services).await {
            tracing::error!("Failed to update active services: {}", e);
        }
        Ok(())
    }

    async fn get_service_status(
        &self,
        service: &ServiceConfig,
    ) -> Result<rpc::DpuExtensionServiceStatusObservation> {
        let res = self.get_pod_status(service).await;
        match res {
            Ok(status) => Ok(status),
            Err(e) => Ok(rpc::DpuExtensionServiceStatusObservation {
                service_id: service.id.to_string(),
                service_type: service.service_type as i32,
                service_name: service.id.to_string(),
                version: service.version.to_string(),
                removed: service.removed.clone(),
                state: rpc::DpuExtensionServiceDeploymentStatus::DpuExtensionServiceError as i32,
                components: Vec::new(),
                message: e.to_string(),
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use uuid::Uuid;

    use super::*;
    use crate::extension_services::dpu_extension_service_observability::{
        DpuExtensionServiceObservability, DpuExtensionServiceObservabilityConfig,
        DpuExtensionServiceObservabilityConfigType,
        DpuExtensionServiceObservabilityConfigTypeLogging,
        DpuExtensionServiceObservabilityConfigTypePrometheus,
    };

    const OBVS_ERR_FILE: &str = "/tmp/extensions_service_observability.err";

    const OBVS_GOLDEN_FILE_CONTENTS: &str =
        include_str!("../../templates/tests/dpu_extension_service_observability.expected");

    #[test]
    fn test_k8s_pod_handler_get_pod_spec_path() {
        let handler = KubernetesPodServicesHandler::default();

        let service_id = "00000000-0000-0000-0000-000000000000";
        let service_version = 1;

        let path = handler.get_pod_spec_path(service_id, service_version);
        assert_eq!(
            path,
            PathBuf::from("/etc/kubelet.d/extservice_00000000-0000-0000-0000-000000000000_1.yaml")
        );

        let path = handler.get_pod_spec_path(service_id, 999999);
        assert_eq!(
            path,
            PathBuf::from(
                "/etc/kubelet.d/extservice_00000000-0000-0000-0000-000000000000_999999.yaml"
            )
        );

        let service_id2 = "123e4567-e89b-12d3-a456-426614174000";
        let path = handler.get_pod_spec_path(service_id2, 1);
        assert_eq!(
            path,
            PathBuf::from("/etc/kubelet.d/extservice_123e4567-e89b-12d3-a456-426614174000_1.yaml")
        );
    }

    #[tokio::test]
    async fn test_k8s_pod_handler_inject_labels() {
        // Test with valid YAML that has metadata but no labels
        let yaml = r#"apiVersion: v1
kind: Pod
metadata:
  name: test-pod
spec:
  containers:
  - name: test-container
    image: test-image:latest
"#;
        let service_id = "00000000-0000-0000-0000-000000000000";
        let version = 5;

        let result = KubernetesPodServicesHandler::inject_labels(yaml, service_id, version);
        assert!(result.is_ok());

        let labeled_yaml = result.unwrap();
        let parsed: Value = serde_yaml::from_str(&labeled_yaml).unwrap();

        // Verify labels were added
        let labels = parsed
            .get("metadata")
            .and_then(|m| m.get("labels"))
            .and_then(|l| l.as_mapping())
            .unwrap();
        assert!(
            labels
                .iter()
                .all(|(k, v)| k.as_str().is_some() && v.as_str().is_some())
        );

        assert_eq!(
            labels.get(Value::from("extservice-id")),
            Some(&Value::from(service_id))
        );
        assert_eq!(
            labels.get(Value::from("extservice-version")),
            Some(&Value::from(version.to_string()))
        );

        // Test with YAML that already has labels
        let yaml_with_labels = r#"apiVersion: v1
kind: Pod
metadata:
  name: test-pod
  labels:
    key1: value1
    key2: value2
spec:
  containers:
  - name: test-container
    image: nginx:latest
"#;

        let result =
            KubernetesPodServicesHandler::inject_labels(yaml_with_labels, service_id, version);
        assert!(result.is_ok());

        let labeled_yaml = result.unwrap();
        let parsed: Value = serde_yaml::from_str(&labeled_yaml).unwrap();

        let labels = parsed
            .get("metadata")
            .and_then(|m| m.get("labels"))
            .and_then(|l| l.as_mapping())
            .unwrap();

        // Verify our labels were added
        assert_eq!(
            labels.get(Value::from("extservice-id")),
            Some(&Value::from(service_id))
        );
        assert_eq!(
            labels.get(Value::from("extservice-version")),
            Some(&Value::from(version.to_string()))
        );

        // Verify existing labels are preserved
        assert_eq!(
            labels.get(Value::from("key1")),
            Some(&Value::from("value1"))
        );
        assert_eq!(
            labels.get(Value::from("key2")),
            Some(&Value::from("value2"))
        );

        // Test with invalid YAML
        let invalid_yaml = "invalid yaml";
        let result = KubernetesPodServicesHandler::inject_labels(invalid_yaml, service_id, version);
        assert!(result.is_err());

        // Test with YAML missing metadata
        let yaml_no_metadata = r#"apiVersion: v1
kind: Pod
spec:
  containers:
  - name: test-container
    image: nginx:latest
"#;
        let result =
            KubernetesPodServicesHandler::inject_labels(yaml_no_metadata, service_id, version);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("metadata"));
    }

    #[test]
    fn test_k8s_pod_handler_parse_state() {
        let handler = KubernetesPodServicesHandler::default();

        assert_eq!(
            handler.parse_state(container::ContainerState::Running),
            "RUNNING"
        );
        assert_eq!(
            handler.parse_state(container::ContainerState::Exited),
            "EXITED"
        );
        assert_eq!(
            handler.parse_state(container::ContainerState::Created),
            "CREATED"
        );
        assert_eq!(
            handler.parse_state(container::ContainerState::Unknown),
            "UNKNOWN"
        );
    }

    #[test]
    fn test_k8s_pod_handler_generate_credential_provider_config() {
        let handler = KubernetesPodServicesHandler::default();

        // Note the trailing slash on the first key — it should be trimmed.
        let mut creds = std::collections::HashMap::new();
        creds.insert(
            "nvcr.io/nv-ngn/sdn/".to_string(),
            UsernamePassword {
                username: "user1".to_string(),
                password: "pass1".to_string(),
            },
        );
        creds.insert(
            "nvcr.io/nvforge".to_string(),
            UsernamePassword {
                username: "user2".to_string(),
                password: "pass2".to_string(),
            },
        );

        let cfg = handler
            .generate_credential_provider_config(&creds)
            .expect("config should be generated");
        let v: serde_json::Value = serde_json::from_str(&cfg).expect("config should be valid JSON");

        assert_eq!(v["apiVersion"], "kubelet.config.k8s.io/v1");
        assert_eq!(v["kind"], "CredentialProviderConfig");

        let providers = v["providers"].as_array().expect("providers must be array");
        assert_eq!(providers.len(), 1);
        let p = &providers[0];
        assert_eq!(p["name"], "cred-provider");
        assert_eq!(p["apiVersion"], "credentialprovider.kubelet.k8s.io/v1");

        let imgs = p["matchImages"]
            .as_array()
            .expect("matchImages must be array");
        let got: std::collections::HashSet<_> = imgs
            .iter()
            .map(|x| x.as_str().unwrap().to_string())
            .collect();
        let want: std::collections::HashSet<_> = [
            "nvcr.io/nv-ngn/sdn".to_string(),
            "nvcr.io/nvforge".to_string(),
        ]
        .into_iter()
        .collect();
        assert_eq!(got, want);

        assert_eq!(p["defaultCacheDuration"], "10m");
    }

    #[test]
    fn test_k8s_pod_handler_get_service_id_and_version_from_filename() {
        // Test with valid filename
        let filename = "extservice_550e8400-e29b-41d4-a716-446655440000_5.yaml";
        let result =
            KubernetesPodServicesHandler::get_service_id_and_version_from_filename(filename);

        assert!(result.is_some());
        let (id, version) = result.unwrap();
        assert_eq!(id.to_string(), "550e8400-e29b-41d4-a716-446655440000");
        assert_eq!(version, 5);

        // Test with invalid format
        assert!(
            KubernetesPodServicesHandler::get_service_id_and_version_from_filename("invalid.yaml")
                .is_none()
        );

        // Test with invalid UUID
        assert!(
            KubernetesPodServicesHandler::get_service_id_and_version_from_filename(
                "extservice_notauuid_5.yaml"
            )
            .is_none()
        );

        // Test with invalid version
        assert!(
            KubernetesPodServicesHandler::get_service_id_and_version_from_filename(
                "extservice_550e8400-e29b-41d4-a716-446655440000_notanumber.yaml"
            )
            .is_none()
        );
    }

    #[test]
    fn test_k8s_pod_handler_aggregate_status_all_running() {
        let handler = KubernetesPodServicesHandler::default();
        let statuses = vec!["RUNNING".to_string(), "RUNNING".to_string()];

        let status = handler.aggregate_status("SANDBOX_READY", &statuses, true);
        assert_eq!(
            status,
            rpc::DpuExtensionServiceDeploymentStatus::DpuExtensionServiceRunning
        );
    }

    #[test]
    fn test_k8s_pod_handler_aggregate_status_no_containers() {
        let handler = KubernetesPodServicesHandler::default();
        let statuses: Vec<String> = vec![];

        // Expected to be deployed: should be PENDING
        let status = handler.aggregate_status("SANDBOX_READY", &statuses, true);
        assert_eq!(
            status,
            rpc::DpuExtensionServiceDeploymentStatus::DpuExtensionServicePending
        );

        // Not expected to be deployed: should be TERMINATED
        let status = handler.aggregate_status("SANDBOX_READY", &statuses, false);
        assert_eq!(
            status,
            rpc::DpuExtensionServiceDeploymentStatus::DpuExtensionServiceTerminated
        );
    }

    #[test]
    fn test_observability_config() {
        let configs = DpuExtensionServiceObservability {
            configs: vec![
                // The first two should be de-duped.
                DpuExtensionServiceObservabilityConfig {
                    name: None,
                    config: DpuExtensionServiceObservabilityConfigType::Prometheus(
                        DpuExtensionServiceObservabilityConfigTypePrometheus {
                            endpoint: "https://localhost:9999".to_string(),
                            scrape_interval_seconds: 1,
                        },
                    ),
                },
                DpuExtensionServiceObservabilityConfig {
                    name: None,
                    config: DpuExtensionServiceObservabilityConfigType::Prometheus(
                        DpuExtensionServiceObservabilityConfigTypePrometheus {
                            endpoint: "https://localhost:9999".to_string(),
                            scrape_interval_seconds: 1,
                        },
                    ),
                },
                // The next two should be seen as unique and both show in the final config.
                DpuExtensionServiceObservabilityConfig {
                    name: Some("logging_uniq1".to_string()),
                    config: DpuExtensionServiceObservabilityConfigType::Logging(
                        DpuExtensionServiceObservabilityConfigTypeLogging {
                            path: "/var/log/someservicelog".to_string(),
                        },
                    ),
                },
                DpuExtensionServiceObservabilityConfig {
                    name: Some("logging_uniq2".to_string()),
                    config: DpuExtensionServiceObservabilityConfigType::Logging(
                        DpuExtensionServiceObservabilityConfigTypeLogging {
                            path: "/var/log/anotherservicelog".to_string(),
                        },
                    ),
                },
            ],
        };

        let content = dpu_extension_service_observability::build(
            Uuid::new_v4(),
            "test_service".to_string(),
            &configs,
        );

        let content = content.unwrap();

        let _yaml_obj: serde_yaml::Value = serde_yaml::from_str(&content)
            .inspect_err(|_| {
                std::fs::write(OBVS_ERR_FILE, content.clone()).unwrap();
                println!("YAML parser error. Output written to {OBVS_ERR_FILE}");
            })
            .unwrap();

        let r = crate::util::compare_lines(&content, OBVS_GOLDEN_FILE_CONTENTS, None);
        eprint!(
            "Content does not match expectations. Diff output:\n{}",
            r.report()
        );
        assert!(r.is_identical());
    }
}
