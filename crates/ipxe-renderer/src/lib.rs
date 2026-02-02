/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */

use sha2::{Digest, Sha256};
use std::collections::HashMap;

/// iPXE OS definition with template-based rendering support
#[derive(Debug, Clone)]
pub struct IpxeOs {
    //pub id: String, // Not needed yet since we don't store in DB
    pub name: String,
    pub description: Option<String>,
    pub hash: String,
    pub tenant_id: Option<String>,
    //pub scope: OsScope, // Not needed yet since we don't store in DB
    pub ipxe_template_name: String,
    pub parameters: Vec<IpxeOsParameter>,
    pub artifacts: Vec<IpxeOsArtifact>,
    //pub created: String, // Not needed yet since we don't store in DB
    //pub updated: String, // Not needed yet since we don't store in DB
    //pub created_by: String, // Not needed yet since we don't store in DB
}

/// OS scope enum
#[derive(Debug, Clone, PartialEq)]
pub enum OsScope {
    Unspecified,
    Global, // Cloud-managed, synced to sites
    Local,  // Site-managed, editable locally
}

/// Parameter for iPXE template substitution
#[derive(Debug, Clone, PartialEq)]
pub struct IpxeOsParameter {
    pub name: String,
    pub value: String,
}

/// Artifact cache strategy
#[derive(Debug, Clone, PartialEq)]
pub enum ArtifactCacheStrategy {
    Unspecified,
    CacheAsNeeded, // Download and cache artifact locally per policy (default)
    LocalOnly,     // Artifact can only be used locally, fail if not available
    RemoteOnly,    // Always fetch from remote URL, never cache locally
} 

/// Remote artifact to allow awareness for potential local caching/proxy
#[derive(Debug, Clone)]
pub struct IpxeOsArtifact {
    pub name: String,
    pub url: String,
    pub sha: Option<String>,
    pub auth_type: Option<String>,
    pub auth_token: Option<String>,
    pub cache_strategy: ArtifactCacheStrategy,
    pub local_url: Option<String>,
}

/// iPXE script template definition
#[derive(Debug, Clone)]
pub struct IpxeScriptTemplate {
    pub name: String,
    pub description: String,
    pub template: String, // iPXE script template: `#!ipxe\n...`
    pub reserved_params: Vec<String>,
    pub required_params: Vec<String>,
}

/// Error types for iPXE OS rendering
#[derive(Debug, thiserror::Error)]
pub enum IpxeOsError {
    #[error("Template not found: {0}")]
    TemplateNotFound(String),

    #[error("Reserved parameter found in OS definition: {0}")]
    ReservedParameterFound(String),

    #[error("Required parameter missing or empty: {0}")]
    RequiredParameterMissing(String),

    #[error("Optional parameters provided but {{{{extra}}}} not in template")]
    ExtraParametersNotSupported,

    #[error("Hash mismatch: expected {expected}, got {actual}")]
    HashMismatch { expected: String, actual: String },

    #[error("Artifact not found: {0}")]
    ArtifactNotFound(String),
}

pub type Result<T> = std::result::Result<T, IpxeOsError>;

/// IpxeOsRenderer is the trait for rendering IPXEOS objects to iPXE scripts
pub trait IpxeOsRenderer {
    /// Render generates the final iPXE script from an IpxeOs object.
    /// `reserved_params` must contain exactly the reserved parameters defined
    /// in the template (provided by carbide-core).
    fn render(&self, ipxeos: &IpxeOs, reserved_params: &[IpxeOsParameter]) -> Result<String>;

    /// RenderWithArtifactSubstitution generates the final iPXE script with
    /// artifact URLs replaced by local cached URLs when available.
    /// `reserved_params` must contain exactly the reserved parameters defined
    /// in the template (provided by carbide-core).
    fn render_with_artifact_substitution(
        &self,
        ipxeos: &IpxeOs,
        reserved_params: &[IpxeOsParameter],
    ) -> Result<String>;

    /// GetTemplate returns a template by name
    fn get_template(&self, name: &str) -> Option<&IpxeScriptTemplate>;

    /// ListTemplates returns all available template names
    fn list_templates(&self) -> Vec<String>;

    /// Validate checks if an IpxeOs object is valid for rendering.
    /// Returns error if:
    /// - Reserved parameters appear in OS definition parameters or artifacts
    /// - Required parameters/artifacts are missing or empty
    /// - Optional parameters are provided but {{extra}} not in template
    /// - Hash does not match hash in OS definition
    fn validate(&self, ipxeos: &IpxeOs) -> Result<()>;

    /// Hash returns a deterministic hash of an IpxeOs object.
    /// Includes: template name, all parameters, and artifact fields
    /// except cache_strategy, local_url, and hash field itself.
    fn hash(&self, ipxeos: &IpxeOs) -> String;

    /// FabricateLocalURLs generates local URLs for artifacts based on specific rules:
    /// - If URL contains a variable: skip (already local)
    /// - If CacheStrategy is REMOTE_ONLY: skip (cannot be cached)
    /// - Otherwise: generate ${base-url}/filename where filename is:
    ///   - SHA256 of the artifact's sha field (if present)
    ///   - SHA256 of the artifact record (if sha is empty) as placeholder
    fn fabricate_local_urls(&self, ipxeos: &IpxeOs) -> IpxeOs;
}

/// Default implementation of IpxeOsRenderer
pub struct DefaultIpxeOsRenderer {
    templates: HashMap<String, IpxeScriptTemplate>,
}

impl DefaultIpxeOsRenderer {
    pub fn new() -> Self {
        let mut templates = HashMap::new();

        // Add default templates
        templates.insert(
            "qcow-image".to_string(),
            IpxeScriptTemplate {
                name: "qcow-image".to_string(),
                template: r#"#!ipxe
# Generic multi-platform template iPXE script for qcow images

# 1. Detect architecture using buildarch
# Standard values are 'x86_64' for Intel/AMD and 'arm64' for AArch64
iseq ${buildarch} x86_64 && set arch x86_64 ||
iseq ${buildarch} arm64  && set arch aarch64 || set arch unknown

# 2. Safety check
iseq ${arch} unknown && echo "Unsupported architecture!" && exit 1

# 3. Set base URL for local artifacts and console specific to hardware:
set base_url {{base_url}}
set console {{console}}

# 4. Boot qcow-imager with parameters:
chain ${base_url}/internal/${buildarch}/qcow-imager.efi loglevel=7 console=tty0 pci=realloc=off console={{console}} image_url={{image_url}} {{extra}}
boot
"#.to_string(),
                required_params: vec!["image_url".to_string()],
                reserved_params: vec!["base_url".to_string(), "console".to_string()],
                description: "Template for booting qcow images using qcow-imager.efi".to_string(),
            },
        );

        templates.insert(
            "ubuntu-autoinstall".to_string(),
            IpxeScriptTemplate {
                name: "ubuntu-autoinstall".to_string(),
                template: r#"#!ipxe
# Ubuntu autoinstall template

set base_url {{base_url}}
set console {{console}}

kernel {{kernel}} ip=dhcp url={{install_iso}} autoinstall ds=nocloud-net;s=${base_url}/user-data/ console={{console}}
initrd {{initrd}}
boot
"#.to_string(),
                required_params: vec!["kernel".to_string(), "initrd".to_string(), "install_iso".to_string()],
                reserved_params: vec!["base_url".to_string(), "console".to_string()],
                description: "Template for Ubuntu autoinstall".to_string(),
            },
        );

        Self { templates }
    }

    pub fn with_templates(templates: HashMap<String, IpxeScriptTemplate>) -> Self {
        Self { templates }
    }
}

impl Default for DefaultIpxeOsRenderer {
    fn default() -> Self {
        Self::new()
    }
}

impl IpxeOsRenderer for DefaultIpxeOsRenderer {
    fn render(&self, ipxeos: &IpxeOs, reserved_params: &[IpxeOsParameter]) -> Result<String> {
        // Validate first
        self.validate(ipxeos)?;

        // Get template
        let template = self
            .get_template(&ipxeos.ipxe_template_name)
            .ok_or_else(|| IpxeOsError::TemplateNotFound(ipxeos.ipxe_template_name.clone()))?;

        // Build parameter map
        let mut param_map: HashMap<String, String> = HashMap::new();

        // Add user-provided parameters
        for param in &ipxeos.parameters {
            param_map.insert(param.name.clone(), param.value.clone());
        }

        // Add reserved parameters (override any user params with same name)
        for param in reserved_params {
            param_map.insert(param.name.clone(), param.value.clone());
        }

        // Replace parameters in template
        let mut result = template.template.clone();
        for (name, value) in &param_map {
            let placeholder = format!("{{{{{}}}}}", name);
            result = result.replace(&placeholder, value);
        }

        // Handle {{extra}} placeholder for additional parameters
        if result.contains("{{extra}}") {
            // Collect parameters that weren't explicitly replaced
            let used_params: std::collections::HashSet<_> = template
                .required_params
                .iter()
                .chain(template.reserved_params.iter())
                .collect();

            let extra_params: Vec<String> = ipxeos
                .parameters
                .iter()
                .filter(|p| !used_params.contains(&p.name))
                .filter(|p| !p.value.is_empty()) // Filter out empty values
                .map(|p| format!("{}={}", p.name, p.value))
                .collect();

            result = result.replace("{{extra}}", &extra_params.join(" "));
        }

        // Post-processing: replace multiple spaces with single space
        while result.contains("  ") {
            result = result.replace("  ", " ");
        }

        // Trim trailing spaces from each line
        result = result
            .lines()
            .map(|line| line.trim_end())
            .collect::<Vec<_>>()
            .join("\n");

        Ok(result)
    }

    fn render_with_artifact_substitution(
        &self,
        ipxeos: &IpxeOs,
        reserved_params: &[IpxeOsParameter],
    ) -> Result<String> {
        // Validate first
        self.validate(ipxeos)?;

        // Get template
        let template = self
            .get_template(&ipxeos.ipxe_template_name)
            .ok_or_else(|| IpxeOsError::TemplateNotFound(ipxeos.ipxe_template_name.clone()))?;

        // Build parameter map
        let mut param_map: HashMap<String, String> = HashMap::new();

        // Add user-provided parameters
        for param in &ipxeos.parameters {
            param_map.insert(param.name.clone(), param.value.clone());
        }

        // Add artifact URLs (prefer local_url if available)
        for artifact in &ipxeos.artifacts {
            let url = artifact.local_url.as_ref().unwrap_or(&artifact.url);
            param_map.insert(artifact.name.clone(), url.clone());
        }

        // Add reserved parameters (override any user params with same name)
        for param in reserved_params {
            param_map.insert(param.name.clone(), param.value.clone());
        }

        // Replace parameters in template
        let mut result = template.template.clone();
        for (name, value) in &param_map {
            let placeholder = format!("{{{{{}}}}}", name);
            result = result.replace(&placeholder, value);
        }

        // Handle {{extra}} placeholder for additional parameters
        if result.contains("{{extra}}") {
            // Collect parameters that weren't explicitly replaced
            let mut used_params: std::collections::HashSet<_> = template
                .required_params
                .iter()
                .chain(template.reserved_params.iter())
                .collect();

            // Also consider artifact names as used
            for artifact in &ipxeos.artifacts {
                used_params.insert(&artifact.name);
            }

            let extra_params: Vec<String> = ipxeos
                .parameters
                .iter()
                .filter(|p| !used_params.contains(&p.name))
                .filter(|p| !p.value.is_empty()) // Filter out empty values
                .map(|p| format!("{}={}", p.name, p.value))
                .collect();

            result = result.replace("{{extra}}", &extra_params.join(" "));
        }

        // Post-processing: replace multiple spaces with single space
        while result.contains("  ") {
            result = result.replace("  ", " ");
        }

        // Trim trailing spaces from each line
        result = result
            .lines()
            .map(|line| line.trim_end())
            .collect::<Vec<_>>()
            .join("\n");

        Ok(result)
    }

    fn get_template(&self, name: &str) -> Option<&IpxeScriptTemplate> {
        self.templates.get(name)
    }

    fn list_templates(&self) -> Vec<String> {
        self.templates.keys().cloned().collect()
    }

    fn validate(&self, ipxeos: &IpxeOs) -> Result<()> {
        // Get template
        let template = self
            .get_template(&ipxeos.ipxe_template_name)
            .ok_or_else(|| IpxeOsError::TemplateNotFound(ipxeos.ipxe_template_name.clone()))?;

        // Check for reserved parameters in OS definition
        for param in &ipxeos.parameters {
            if template.reserved_params.contains(&param.name) {
                return Err(IpxeOsError::ReservedParameterFound(param.name.clone()));
            }
        }

        // Check for required parameters
        for required_param in &template.required_params {
            let found = ipxeos
                .parameters
                .iter()
                .any(|p| &p.name == required_param && !p.value.is_empty());

            if !found {
                // Check if it's an artifact
                let artifact_found = ipxeos.artifacts.iter().any(|a| &a.name == required_param);

                if !artifact_found {
                    return Err(IpxeOsError::RequiredParameterMissing(
                        required_param.clone(),
                    ));
                }
            }
        }

        // Check if optional parameters are provided but {{extra}} is not in template
        let used_params: std::collections::HashSet<_> = template
            .required_params
            .iter()
            .chain(template.reserved_params.iter())
            .collect();

        let has_extra_params = ipxeos
            .parameters
            .iter()
            .any(|p| !used_params.contains(&p.name));

        if has_extra_params && !template.template.contains("{{extra}}") {
            return Err(IpxeOsError::ExtraParametersNotSupported);
        }

        // Validate hash
        let computed_hash = self.hash(ipxeos);
        if computed_hash != ipxeos.hash {
            return Err(IpxeOsError::HashMismatch {
                expected: ipxeos.hash.clone(),
                actual: computed_hash,
            });
        }

        Ok(())
    }

    fn hash(&self, ipxeos: &IpxeOs) -> String {
        let mut hasher = Sha256::new();

        // Hash template name
        hasher.update(ipxeos.ipxe_template_name.as_bytes());

        // Hash parameters (sorted for determinism)
        let mut params = ipxeos.parameters.clone();
        params.sort_by(|a, b| a.name.cmp(&b.name));
        for param in params {
            hasher.update(param.name.as_bytes());
            hasher.update(param.value.as_bytes());
        }

        // Hash artifacts (excluding cache_strategy and local_url)
        let mut artifacts = ipxeos.artifacts.clone();
        artifacts.sort_by(|a, b| a.name.cmp(&b.name));
        for artifact in artifacts {
            hasher.update(artifact.name.as_bytes());
            hasher.update(artifact.url.as_bytes());
            if let Some(sha) = &artifact.sha {
                hasher.update(sha.as_bytes());
            }
            if let Some(auth_type) = &artifact.auth_type {
                hasher.update(auth_type.as_bytes());
            }
            if let Some(auth_token) = &artifact.auth_token {
                hasher.update(auth_token.as_bytes());
            }
        }

        format!("{:x}", hasher.finalize())
    }

    fn fabricate_local_urls(&self, ipxeos: &IpxeOs) -> IpxeOs {
        let mut new_ipxeos = ipxeos.clone();

        for artifact in &mut new_ipxeos.artifacts {
            if artifact.cache_strategy != ArtifactCacheStrategy::RemoteOnly
                && artifact.local_url.is_none()
            {
                // Generate local URL based on artifact name and sha (if available)
                let local_url = if let Some(sha) = &artifact.sha {
                    format!("${{base_url}}/artifacts/{}-{}", artifact.name, sha)
                } else {
                    format!("${{base_url}}/artifacts/{}", artifact.name)
                };
                artifact.local_url = Some(local_url);
            }
        }

        new_ipxeos
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_ipxeos() -> IpxeOs {
        IpxeOs {
            name: "Test OS".to_string(),
            description: Some("Test operating system".to_string()),
            hash: "placeholder".to_string(),
            tenant_id: None,
            ipxe_template_name: "qcow-image".to_string(),
            parameters: vec![IpxeOsParameter {
                name: "image_url".to_string(),
                value: "http://example.com/image.qcow2".to_string(),
            }],
            artifacts: vec![],
        }
    }

    #[test]
    fn test_hash_computation() {
        let renderer = DefaultIpxeOsRenderer::new();
        let mut ipxeos = create_test_ipxeos();

        // Compute hash
        let hash = renderer.hash(&ipxeos);
        ipxeos.hash = hash.clone();

        // Validation should pass
        assert!(renderer.validate(&ipxeos).is_ok());

        // Modify a parameter
        ipxeos.parameters[0].value = "http://example.com/different.qcow2".to_string();

        // Validation should fail due to hash mismatch
        assert!(matches!(
            renderer.validate(&ipxeos),
            Err(IpxeOsError::HashMismatch { .. })
        ));
    }

    #[test]
    fn test_reserved_parameter_validation() {
        let renderer = DefaultIpxeOsRenderer::new();
        let mut ipxeos = create_test_ipxeos();

        // Add a reserved parameter
        ipxeos.parameters.push(IpxeOsParameter {
            name: "base_url".to_string(),
            value: "http://bad.com".to_string(),
        });

        // Update hash
        ipxeos.hash = renderer.hash(&ipxeos);

        // Validation should fail
        assert!(matches!(
            renderer.validate(&ipxeos),
            Err(IpxeOsError::ReservedParameterFound(_))
        ));
    }

    #[test]
    fn test_required_parameter_validation() {
        let renderer = DefaultIpxeOsRenderer::new();
        let mut ipxeos = create_test_ipxeos();

        // Remove required parameter
        ipxeos.parameters.clear();

        // Update hash
        ipxeos.hash = renderer.hash(&ipxeos);

        // Validation should fail
        assert!(matches!(
            renderer.validate(&ipxeos),
            Err(IpxeOsError::RequiredParameterMissing(_))
        ));
    }

    #[test]
    fn test_render_qcow_template() {
        let renderer = DefaultIpxeOsRenderer::new();
        let mut ipxeos = create_test_ipxeos();

        // Update hash
        ipxeos.hash = renderer.hash(&ipxeos);

        let reserved_params = vec![
            IpxeOsParameter {
                name: "base_url".to_string(),
                value: "http://pxe.local".to_string(),
            },
            IpxeOsParameter {
                name: "console".to_string(),
                value: "ttyS0,115200".to_string(),
            },
        ];

        let result = renderer.render(&ipxeos, &reserved_params);
        assert!(result.is_ok());

        let script = result.unwrap();
        assert!(script.contains("http://pxe.local"));
        assert!(script.contains("ttyS0,115200"));
        assert!(script.contains("http://example.com/image.qcow2"));
    }

    #[test]
    fn test_render_with_extra_params() {
        let renderer = DefaultIpxeOsRenderer::new();
        let mut ipxeos = create_test_ipxeos();

        // Add extra parameters
        ipxeos.parameters.push(IpxeOsParameter {
            name: "image_sha".to_string(),
            value: "sha256:abc123".to_string(),
        });
        ipxeos.parameters.push(IpxeOsParameter {
            name: "rootfs_uuid".to_string(),
            value: "12345678".to_string(),
        });

        // Update hash
        ipxeos.hash = renderer.hash(&ipxeos);

        let reserved_params = vec![
            IpxeOsParameter {
                name: "base_url".to_string(),
                value: "http://pxe.local".to_string(),
            },
            IpxeOsParameter {
                name: "console".to_string(),
                value: "ttyS0,115200".to_string(),
            },
        ];

        let result = renderer.render(&ipxeos, &reserved_params);
        assert!(result.is_ok());

        let script = result.unwrap();
        assert!(script.contains("image_sha=sha256:abc123"));
        assert!(script.contains("rootfs_uuid=12345678"));
    }

    #[test]
    fn test_render_ubuntu_autoinstall() {
        let renderer = DefaultIpxeOsRenderer::new();
        let mut ipxeos = IpxeOs {
            name: "Ubuntu 22.04".to_string(),
            description: Some("Ubuntu autoinstall".to_string()),
            hash: "placeholder".to_string(),
            tenant_id: None,
            ipxe_template_name: "ubuntu-autoinstall".to_string(),
            parameters: vec![
                IpxeOsParameter {
                    name: "kernel".to_string(),
                    value: "http://archive.ubuntu.com/ubuntu/dists/jammy/main/installer-amd64/current/legacy-images/netboot/ubuntu-installer/amd64/linux".to_string(),
                },
                IpxeOsParameter {
                    name: "initrd".to_string(),
                    value: "http://archive.ubuntu.com/ubuntu/dists/jammy/main/installer-amd64/current/legacy-images/netboot/ubuntu-installer/amd64/initrd.gz".to_string(),
                },
                IpxeOsParameter {
                    name: "install_iso".to_string(),
                    value: "http://releases.ubuntu.com/22.04/ubuntu-22.04-live-server-amd64.iso".to_string(),
                },
            ],
            artifacts: vec![],
        };

        // Update hash
        ipxeos.hash = renderer.hash(&ipxeos);

        let reserved_params = vec![
            IpxeOsParameter {
                name: "base_url".to_string(),
                value: "http://pxe.local".to_string(),
            },
            IpxeOsParameter {
                name: "console".to_string(),
                value: "ttyS0,115200".to_string(),
            },
        ];

        let result = renderer.render(&ipxeos, &reserved_params);
        assert!(result.is_ok());

        let script = result.unwrap();
        assert!(script.contains("kernel http://archive.ubuntu.com"));
        assert!(script.contains("initrd http://archive.ubuntu.com"));
        assert!(script.contains("url=http://releases.ubuntu.com"));
    }

    #[test]
    fn test_render_with_artifact_substitution() {
        let renderer = DefaultIpxeOsRenderer::new();
        let mut ipxeos = IpxeOs {
            name: "Ubuntu with artifacts".to_string(),
            description: Some("Ubuntu with cached artifacts".to_string()),
            hash: "placeholder".to_string(),
            tenant_id: None,
            ipxe_template_name: "ubuntu-autoinstall".to_string(),
            parameters: vec![
                IpxeOsParameter {
                    name: "install_iso".to_string(),
                    value: "http://releases.ubuntu.com/22.04/ubuntu-22.04-live-server-amd64.iso".to_string(),
                },
            ],
            artifacts: vec![
                IpxeOsArtifact {
                    name: "kernel".to_string(),
                    url: "http://archive.ubuntu.com/ubuntu/dists/jammy/main/installer-amd64/current/legacy-images/netboot/ubuntu-installer/amd64/linux".to_string(),
                    sha: Some("sha256:abc123".to_string()),
                    auth_type: None,
                    auth_token: None,
                    cache_strategy: ArtifactCacheStrategy::CacheAsNeeded,
                    local_url: Some("http://pxe.local/artifacts/kernel-abc123".to_string()),
                },
                IpxeOsArtifact {
                    name: "initrd".to_string(),
                    url: "http://archive.ubuntu.com/ubuntu/dists/jammy/main/installer-amd64/current/legacy-images/netboot/ubuntu-installer/amd64/initrd.gz".to_string(),
                    sha: Some("sha256:def456".to_string()),
                    auth_type: None,
                    auth_token: None,
                    cache_strategy: ArtifactCacheStrategy::CacheAsNeeded,
                    local_url: Some("http://pxe.local/artifacts/initrd-def456".to_string()),
                },
            ],
        };

        // Update hash
        ipxeos.hash = renderer.hash(&ipxeos);

        let reserved_params = vec![
            IpxeOsParameter {
                name: "base_url".to_string(),
                value: "http://pxe.local".to_string(),
            },
            IpxeOsParameter {
                name: "console".to_string(),
                value: "ttyS0,115200".to_string(),
            },
        ];

        let result = renderer.render_with_artifact_substitution(&ipxeos, &reserved_params);
        assert!(result.is_ok());

        let script = result.unwrap();
        // Should use local cached URLs instead of remote URLs
        assert!(script.contains("kernel http://pxe.local/artifacts/kernel-abc123"));
        assert!(script.contains("initrd http://pxe.local/artifacts/initrd-def456"));
    }

    #[test]
    fn test_fabricate_local_urls() {
        let renderer = DefaultIpxeOsRenderer::new();
        let ipxeos = IpxeOs {
            name: "Test with artifacts".to_string(),
            description: Some("Test".to_string()),
            hash: "test-hash".to_string(),
            tenant_id: None,
            ipxe_template_name: "ubuntu-autoinstall".to_string(),
            parameters: vec![],
            artifacts: vec![
                IpxeOsArtifact {
                    name: "kernel".to_string(),
                    url: "http://example.com/kernel".to_string(),
                    sha: Some("sha256:abc123".to_string()),
                    auth_type: None,
                    auth_token: None,
                    cache_strategy: ArtifactCacheStrategy::CacheAsNeeded,
                    local_url: None,
                },
                IpxeOsArtifact {
                    name: "initrd".to_string(),
                    url: "http://example.com/initrd".to_string(),
                    sha: None,
                    auth_type: None,
                    auth_token: None,
                    cache_strategy: ArtifactCacheStrategy::RemoteOnly,
                    local_url: None,
                },
            ],
        };

        let result = renderer.fabricate_local_urls(&ipxeos);

        // First artifact should have local_url generated
        assert!(result.artifacts[0].local_url.is_some());
        assert_eq!(
            result.artifacts[0].local_url.as_ref().unwrap(),
            "${base_url}/artifacts/kernel-sha256:abc123"
        );

        // Second artifact is RemoteOnly, should not have local_url
        assert!(result.artifacts[1].local_url.is_none());
    }

    #[test]
    fn test_list_templates() {
        let renderer = DefaultIpxeOsRenderer::new();
        let templates = renderer.list_templates();

        assert!(templates.contains(&"qcow-image".to_string()));
        assert!(templates.contains(&"ubuntu-autoinstall".to_string()));
        assert_eq!(templates.len(), 2);
    }

    #[test]
    fn test_get_template() {
        let renderer = DefaultIpxeOsRenderer::new();

        let template = renderer.get_template("qcow-image");
        assert!(template.is_some());
        assert_eq!(template.unwrap().name, "qcow-image");

        let missing = renderer.get_template("nonexistent");
        assert!(missing.is_none());
    }
}
