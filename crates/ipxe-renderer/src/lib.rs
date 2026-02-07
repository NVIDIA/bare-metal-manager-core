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
use serde::Deserialize;

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
#[derive(Debug, Clone, Deserialize)]
pub struct IpxeScriptTemplate {
    pub name: String,
    pub description: String,
    pub template: String, // iPXE script template: `#!ipxe\n...`
    #[serde(default)]
    pub reserved_params: Vec<String>,
    #[serde(default)]
    pub required_params: Vec<String>,
    #[serde(default)]
    pub required_artifacts: Vec<String>,
}

/// Template collection loaded from YAML
#[derive(Debug, Deserialize)]
struct TemplateCollection {
    templates: Vec<IpxeScriptTemplate>,
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

    #[error("Missing reserved parameter: {0}")]
    MissingReservedParameter(String),

    #[error("Unexpected reserved parameter: {0}")]
    UnexpectedReservedParameter(String),

    #[error("Unreplaced placeholders found: {0}")]
    UnreplacedPlaceholders(String),
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
    /// - Required parameters are missing or empty
    /// - Required artifacts are missing or empty
    /// - Optional parameters are provided but {{extra}} not in template
    /// - Hash does not match hash in OS definition
    fn validate(&self, ipxeos: &IpxeOs) -> Result<()>;

    /// Hash returns a deterministic hash of an IpxeOs object.
    /// Includes: template name, all parameters, and artifact fields
    /// Excludes: cache_strategy, local_url, and hash field itself.
    fn hash(&self, ipxeos: &IpxeOs) -> String;

    /// FabricateLocalURLs generates local URLs for artifacts based on specific rules:
    /// - If URL contains a variable (${...} or {{...}}): skip (already local)
    /// - If CacheStrategy is REMOTE_ONLY: skip (cannot be cached)
    /// - If local_url already set: skip (already processed)
    /// - Otherwise: generate ${base_url}/[hash] where hash is:
    ///   - sha field of the artifact (if present)
    ///   - SHA256 hash of the artifact record + name + URL (if sha is empty)
    fn fabricate_local_urls(&self, ipxeos: &IpxeOs) -> IpxeOs;
}

/// Default implementation of IpxeOsRenderer
pub struct DefaultIpxeOsRenderer {
    templates: HashMap<String, IpxeScriptTemplate>,
}

impl DefaultIpxeOsRenderer {
    pub fn new() -> Self {
        // Load templates from embedded YAML file at compile time
        const TEMPLATES_YAML: &str = include_str!("../templates.yaml");
        
        let template_collection: TemplateCollection = serde_yaml::from_str(TEMPLATES_YAML)
            .expect("Failed to parse templates.yaml - this is a compile-time error");
        
        let templates = template_collection
            .templates
            .into_iter()
            .map(|t| (t.name.clone(), t))
            .collect();

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

        // Validate reserved parameters match template requirements
        self.validate_reserved_params(reserved_params, &template)?;

        // Occurrence-based parameter consumption (case-insensitive matching)
        // Build consumption map: lowercase keys, values in order that will be consumed
        let mut consumption_map: HashMap<String, Vec<String>> = HashMap::new();
        let mut consumed_indices: std::collections::HashSet<usize> = std::collections::HashSet::new();
        
        // Step 1: Consume parameters for required_params (in order with duplicates)
        // Case-insensitive matching using lowercase
        for required_name in &template.required_params {
            let required_lower = required_name.to_lowercase();
            // Find next unconsumed parameter with this name (case-insensitive)
            for (idx, param) in ipxeos.parameters.iter().enumerate() {
                if param.name.to_lowercase() == required_lower && !consumed_indices.contains(&idx) && !param.value.is_empty() {
                    consumption_map
                        .entry(required_lower.clone())
                        .or_insert_with(Vec::new)
                        .push(param.value.clone());
                    consumed_indices.insert(idx);
                    break;
                }
            }
        }
        
        // Step 2: Add reserved parameters (they override and are always provided)
        // Case-insensitive matching
        for reserved_name in &template.reserved_params {
            let reserved_lower = reserved_name.to_lowercase();
            // Find the reserved param value from provided reserved_params (case-insensitive)
            if let Some(reserved_param) = reserved_params.iter().find(|p| p.name.to_lowercase() == reserved_lower) {
                consumption_map
                    .entry(reserved_lower)
                    .or_insert_with(Vec::new)
                    .push(reserved_param.value.clone());
            }
        }
        
        // Step 3: Replace placeholders in template (case-insensitive)
        // Template placeholders should be lowercase
        let mut result = template.template.clone();
        
        // Get all unique placeholder names
        let mut processed_names: std::collections::HashSet<String> = std::collections::HashSet::new();
        
        // For each param name in consumption_map (already lowercase), replace all occurrences
        for (param_name_lower, values) in &consumption_map {
            if processed_names.contains(param_name_lower) {
                continue;
            }
            processed_names.insert(param_name_lower.clone());
            
            // Replace occurrences one by one (placeholder should be lowercase)
            let placeholder = format!("{{{{{}}}}}", param_name_lower);
            for value in values {
                if let Some(pos) = result.find(&placeholder) {
                    result.replace_range(pos..pos + placeholder.len(), value);
                }
            }
        }

        // Step 4: Handle {{extra}} placeholder for unconsumed parameters
        // PRESERVE ORIGINAL CASE for parameter names in {{extra}}
        if result.contains("{{extra}}") {
            let mut extra_params: Vec<String> = Vec::new();
            
            // Collect all unconsumed parameters (preserve original case)
            for (idx, param) in ipxeos.parameters.iter().enumerate() {
                if !consumed_indices.contains(&idx) && !param.value.is_empty() {
                    extra_params.push(format!("{}={}", param.name, param.value));  // Original case preserved
                }
            }

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

        // Check for unreplaced placeholders
        self.check_unreplaced_placeholders(&result)?;

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

        // Validate reserved parameters match template requirements
        self.validate_reserved_params(reserved_params, &template)?;

        // Occurrence-based parameter consumption (with artifact substitution, case-insensitive)
        let mut consumption_map: HashMap<String, Vec<String>> = HashMap::new();
        let mut consumed_param_indices: std::collections::HashSet<usize> = std::collections::HashSet::new();
        let mut consumed_artifact_indices: std::collections::HashSet<usize> = std::collections::HashSet::new();
        
        // Step 1: Consume parameters for required_params (in order with duplicates, case-insensitive)
        for required_name in &template.required_params {
            let required_lower = required_name.to_lowercase();
            // Find next unconsumed parameter with this name (case-insensitive)
            for (idx, param) in ipxeos.parameters.iter().enumerate() {
                if param.name.to_lowercase() == required_lower && !consumed_param_indices.contains(&idx) && !param.value.is_empty() {
                    consumption_map
                        .entry(required_lower.clone())
                        .or_insert_with(Vec::new)
                        .push(param.value.clone());
                    consumed_param_indices.insert(idx);
                    break;
                }
            }
        }
        
        // Step 2: Consume artifacts for required_artifacts (in order with duplicates, case-insensitive)
        for required_artifact_name in &template.required_artifacts {
            let required_artifact_lower = required_artifact_name.to_lowercase();
            // Find next unconsumed artifact with this name (case-insensitive)
            for (idx, artifact) in ipxeos.artifacts.iter().enumerate() {
                if artifact.name.to_lowercase() == required_artifact_lower && !consumed_artifact_indices.contains(&idx) {
                    let url = artifact.local_url.as_ref().unwrap_or(&artifact.url);
                    consumption_map
                        .entry(required_artifact_lower.clone())
                        .or_insert_with(Vec::new)
                        .push(url.clone());
                    consumed_artifact_indices.insert(idx);
                    break;
                }
            }
        }
        
        // Step 3: Add reserved parameters (they override and are always provided, case-insensitive)
        for reserved_name in &template.reserved_params {
            let reserved_lower = reserved_name.to_lowercase();
            if let Some(reserved_param) = reserved_params.iter().find(|p| p.name.to_lowercase() == reserved_lower) {
                consumption_map
                    .entry(reserved_lower)
                    .or_insert_with(Vec::new)
                    .push(reserved_param.value.clone());
            }
        }
        
        // Step 4: Replace placeholders in template (lowercase keys)
        let mut result = template.template.clone();
        let mut processed_names: std::collections::HashSet<String> = std::collections::HashSet::new();
        
        for (param_name_lower, values) in &consumption_map {
            if processed_names.contains(param_name_lower) {
                continue;
            }
            processed_names.insert(param_name_lower.clone());
            
            // Placeholder should be lowercase
            let placeholder = format!("{{{{{}}}}}", param_name_lower);
            for value in values {
                if let Some(pos) = result.find(&placeholder) {
                    result.replace_range(pos..pos + placeholder.len(), value);
                }
            }
        }

        // Step 5: Handle {{extra}} placeholder for unconsumed parameters
        // PRESERVE ORIGINAL CASE for parameter names in {{extra}}
        if result.contains("{{extra}}") {
            let mut extra_params: Vec<String> = Vec::new();
            
            // Collect all unconsumed parameters (not artifacts for extra, preserve original case)
            for (idx, param) in ipxeos.parameters.iter().enumerate() {
                if !consumed_param_indices.contains(&idx) && !param.value.is_empty() {
                    extra_params.push(format!("{}={}", param.name, param.value));  // Original case preserved
                }
            }

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

        // Check for unreplaced placeholders
        self.check_unreplaced_placeholders(&result)?;

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

        // Check for globally reserved names: "extra" is reserved for {{extra}} placeholder
        // Names are case-insensitive (normalized to lowercase)
        for param in &ipxeos.parameters {
            if param.name.to_lowercase() == "extra" {
                return Err(IpxeOsError::ReservedParameterFound(
                    format!("'{}' (normalized to 'extra' which is globally reserved for {{{{extra}}}} placeholder)", param.name),
                ));
            }
        }
        
        for artifact in &ipxeos.artifacts {
            if artifact.name.to_lowercase() == "extra" {
                return Err(IpxeOsError::ReservedParameterFound(
                    format!("'{}' (normalized to 'extra' which is globally reserved, cannot be used as artifact name)", artifact.name),
                ));
            }
        }

        // Check for template-specific reserved parameters in OS definition
        // Case-insensitive comparison
        for param in &ipxeos.parameters {
            let param_lower = param.name.to_lowercase();
            for reserved in &template.reserved_params {
                if param_lower == reserved.to_lowercase() {
                    return Err(IpxeOsError::ReservedParameterFound(param.name.clone()));
                }
            }
        }

        // Check for required parameters - count occurrences
        // Build map of required counts for each parameter name (case-insensitive, use lowercase)
        let mut required_param_counts: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
        for required_param in &template.required_params {
            let key = required_param.to_lowercase();
            *required_param_counts.entry(key).or_insert(0) += 1;
        }

        // Count available non-empty parameters and artifacts (case-insensitive comparison)
        for (required_name_lower, required_count) in &required_param_counts {
            let param_count = ipxeos
                .parameters
                .iter()
                .filter(|p| p.name.to_lowercase() == *required_name_lower && !p.value.is_empty())
                .count();
            
            let artifact_count = ipxeos
                .artifacts
                .iter()
                .filter(|a| a.name.to_lowercase() == *required_name_lower)
                .count();
            
            let available_count = param_count + artifact_count;
            
            if available_count < *required_count {
                return Err(IpxeOsError::RequiredParameterMissing(
                    format!("{} (need {} occurrences, have {})", required_name_lower, required_count, available_count),
                ));
            }
        }

        // Check for required artifacts - count occurrences (case-insensitive)
        let mut required_artifact_counts: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
        for required_artifact in &template.required_artifacts {
            let key = required_artifact.to_lowercase();
            *required_artifact_counts.entry(key).or_insert(0) += 1;
        }

        for (required_name_lower, required_count) in &required_artifact_counts {
            let artifact_count = ipxeos
                .artifacts
                .iter()
                .filter(|a| a.name.to_lowercase() == *required_name_lower && !a.url.is_empty())
                .count();

            if artifact_count < *required_count {
                return Err(IpxeOsError::ArtifactNotFound(
                    format!("{} (need {} occurrences, have {})", required_name_lower, required_count, artifact_count),
                ));
            }
        }

        // Check if optional parameters are provided but {{extra}} is not in template
        // Case-insensitive comparison using lowercase
        let used_params_lower: std::collections::HashSet<String> = template
            .required_params
            .iter()
            .chain(template.reserved_params.iter())
            .map(|s| s.to_lowercase())
            .collect();

        let has_extra_params = ipxeos
            .parameters
            .iter()
            .any(|p| !used_params_lower.contains(&p.name.to_lowercase()));

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

        // Hash template name (lowercase for case-insensitivity)
        hasher.update(ipxeos.ipxe_template_name.to_lowercase().as_bytes());

        // Hash parameters (sorted for determinism, names lowercase for case-insensitivity)
        let mut params = ipxeos.parameters.clone();
        params.sort_by(|a, b| a.name.to_lowercase().cmp(&b.name.to_lowercase()));
        for param in params {
            hasher.update(param.name.to_lowercase().as_bytes());  // Lowercase for case-insensitivity
            hasher.update(param.value.as_bytes());  // Value keeps original case
        }

        // Hash artifacts (excluding cache_strategy and local_url, names lowercase)
        let mut artifacts = ipxeos.artifacts.clone();
        artifacts.sort_by(|a, b| a.name.to_lowercase().cmp(&b.name.to_lowercase()));
        for artifact in artifacts {
            hasher.update(artifact.name.to_lowercase().as_bytes());  // Lowercase for case-insensitivity
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
            // Skip if RemoteOnly or already has local_url
            if artifact.cache_strategy == ArtifactCacheStrategy::RemoteOnly
                || artifact.local_url.is_some()
            {
                continue;
            }

            // Skip if URL contains iPXE variable (already local)
            if artifact.url.contains("${") || artifact.url.contains("{{") {
                continue;
            }

            // Generate local URL hash
            let hash = if let Some(sha) = &artifact.sha {
                // Use the sha field directly (it's already a hash/checksum)
                sha.clone()
            } else {
                // Compute SHA256 hash of the artifact record (name + URL)
                let mut hasher = Sha256::new();
                hasher.update(artifact.name.as_bytes());
                hasher.update(artifact.url.as_bytes());
                format!("{:x}", hasher.finalize())
            };

            artifact.local_url = Some(format!("${{base_url}}/{}", hash));
        }

        new_ipxeos
    }
}

impl DefaultIpxeOsRenderer {
    /// Validate that reserved parameters provided match template requirements exactly
    fn validate_reserved_params(
        &self,
        reserved_params: &[IpxeOsParameter],
        template: &IpxeScriptTemplate,
    ) -> Result<()> {
        // Build sets of unique names for comparison (case-insensitive, use lowercase)
        let provided: std::collections::HashSet<String> =
            reserved_params.iter().map(|p| p.name.to_lowercase()).collect();
        let required: std::collections::HashSet<String> =
            template.reserved_params.iter().map(|s| s.to_lowercase()).collect();

        // Check for missing reserved parameters (case-insensitive)
        for required_param in &template.reserved_params {
            let required_lower = required_param.to_lowercase();
            if !provided.contains(&required_lower) {
                return Err(IpxeOsError::MissingReservedParameter(
                    required_param.to_string(),
                ));
            }
        }

        // Check for unexpected reserved parameters (case-insensitive)
        for provided_param in reserved_params {
            let provided_lower = provided_param.name.to_lowercase();
            if !required.contains(&provided_lower) {
                return Err(IpxeOsError::UnexpectedReservedParameter(
                    provided_param.name.clone(),
                ));
            }
        }

        Ok(())
    }

    /// Check if there are any unreplaced placeholders in the result
    fn check_unreplaced_placeholders(&self, result: &str) -> Result<()> {
        // Find all {{...}} patterns
        let mut unreplaced = Vec::new();
        let mut start = 0;
        while let Some(pos) = result[start..].find("{{") {
            let abs_pos = start + pos;
            if let Some(end_pos) = result[abs_pos..].find("}}") {
                let placeholder = &result[abs_pos..abs_pos + end_pos + 2];
                unreplaced.push(placeholder.to_string());
                start = abs_pos + end_pos + 2;
            } else {
                break;
            }
        }

        if !unreplaced.is_empty() {
            return Err(IpxeOsError::UnreplacedPlaceholders(unreplaced.join(", ")));
        }

        Ok(())
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
    fn test_required_artifact_validation() {
        let renderer = DefaultIpxeOsRenderer::new();
        let mut ipxeos = IpxeOs {
            name: "Ubuntu 22.04".to_string(),
            description: Some("Ubuntu autoinstall".to_string()),
            hash: "placeholder".to_string(),
            tenant_id: None,
            ipxe_template_name: "ubuntu-autoinstall".to_string(),
            parameters: vec![IpxeOsParameter {
                name: "install_iso".to_string(),
                value: "http://releases.ubuntu.com/22.04/ubuntu-22.04-live-server-amd64.iso"
                    .to_string(),
            }],
            artifacts: vec![
                // Missing initrd artifact - should cause validation failure
                IpxeOsArtifact {
                    name: "kernel".to_string(),
                    url: "http://example.com/kernel".to_string(),
                    sha: None,
                    auth_type: None,
                    auth_token: None,
                    cache_strategy: ArtifactCacheStrategy::CacheAsNeeded,
                    local_url: None,
                },
            ],
        };

        // Update hash
        ipxeos.hash = renderer.hash(&ipxeos);

        // Validation should fail due to missing initrd artifact
        assert!(matches!(
            renderer.validate(&ipxeos),
            Err(IpxeOsError::ArtifactNotFound(_))
        ));

        // Now add the missing artifact
        ipxeos.artifacts.push(IpxeOsArtifact {
            name: "initrd".to_string(),
            url: "http://example.com/initrd".to_string(),
            sha: None,
            auth_type: None,
            auth_token: None,
            cache_strategy: ArtifactCacheStrategy::CacheAsNeeded,
            local_url: None,
        });

        // Update hash
        ipxeos.hash = renderer.hash(&ipxeos);

        // Validation should now pass
        assert!(renderer.validate(&ipxeos).is_ok());
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
            parameters: vec![IpxeOsParameter {
                name: "install_iso".to_string(),
                value: "http://releases.ubuntu.com/22.04/ubuntu-22.04-live-server-amd64.iso"
                    .to_string(),
            }],
            artifacts: vec![
                IpxeOsArtifact {
                    name: "kernel".to_string(),
                    url: "http://archive.ubuntu.com/ubuntu/dists/jammy/main/installer-amd64/current/legacy-images/netboot/ubuntu-installer/amd64/linux".to_string(),
                    sha: None,
                    auth_type: None,
                    auth_token: None,
                    cache_strategy: ArtifactCacheStrategy::CacheAsNeeded,
                    local_url: None,
                },
                IpxeOsArtifact {
                    name: "initrd".to_string(),
                    url: "http://archive.ubuntu.com/ubuntu/dists/jammy/main/installer-amd64/current/legacy-images/netboot/ubuntu-installer/amd64/initrd.gz".to_string(),
                    sha: None,
                    auth_type: None,
                    auth_token: None,
                    cache_strategy: ArtifactCacheStrategy::CacheAsNeeded,
                    local_url: None,
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
            parameters: vec![IpxeOsParameter {
                name: "install_iso".to_string(),
                value: "http://releases.ubuntu.com/22.04/ubuntu-22.04-live-server-amd64.iso"
                    .to_string(),
            }],
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
            parameters: vec![IpxeOsParameter {
                name: "install_iso".to_string(),
                value: "http://example.com/ubuntu.iso".to_string(),
            }],
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
                IpxeOsArtifact {
                    name: "local-var".to_string(),
                    url: "${base-url}/local.img".to_string(),
                    sha: Some("sha256:local789".to_string()),
                    auth_type: None,
                    auth_token: None,
                    cache_strategy: ArtifactCacheStrategy::CacheAsNeeded,
                    local_url: None,
                },
            ],
        };

        let result = renderer.fabricate_local_urls(&ipxeos);

        // First artifact should have local_url using sha field directly
        assert!(result.artifacts[0].local_url.is_some());
        let local_url = result.artifacts[0].local_url.as_ref().unwrap();
        assert_eq!(local_url, "${base_url}/sha256:abc123");

        // Second artifact is RemoteOnly, should not have local_url
        assert!(result.artifacts[1].local_url.is_none());

        // Third artifact has iPXE variable, should not have local_url
        assert!(result.artifacts[2].local_url.is_none());
    }

    #[test]
    fn test_list_templates() {
        let renderer = DefaultIpxeOsRenderer::new();
        let templates = renderer.list_templates();

        assert!(templates.contains(&"qcow-image".to_string()));
        assert!(templates.contains(&"ubuntu-autoinstall".to_string()));
        assert!(templates.contains(&"DGX OS".to_string()));
        assert!(templates.contains(&"discovery-scout-aarch64-dpu".to_string()));
        assert!(templates.contains(&"discovery-scout-aarch64".to_string()));
        assert!(templates.contains(&"discovery-scout-x86_64".to_string()));
        assert!(templates.contains(&"error-instructions".to_string()));
        assert!(templates.contains(&"exit-instructions".to_string()));
        assert!(templates.contains(&"unknown-host".to_string()));
        assert!(templates.contains(&"whoami".to_string()));
        assert_eq!(templates.len(), 11); // Total templates
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

    #[test]
    fn test_missing_reserved_parameter() {
        let renderer = DefaultIpxeOsRenderer::new();
        let mut ipxeos = create_test_ipxeos();
        ipxeos.hash = renderer.hash(&ipxeos);

        // Template requires base_url and console, but we only provide base_url
        let reserved_params = vec![IpxeOsParameter {
            name: "base_url".to_string(),
            value: "http://pxe.local".to_string(),
        }];

        let result = renderer.render(&ipxeos, &reserved_params);
        assert!(matches!(
            result,
            Err(IpxeOsError::MissingReservedParameter(_))
        ));
    }

    #[test]
    fn test_unexpected_reserved_parameter() {
        let renderer = DefaultIpxeOsRenderer::new();
        let mut ipxeos = create_test_ipxeos();
        ipxeos.hash = renderer.hash(&ipxeos);

        // Provide extra reserved parameter not in template
        let reserved_params = vec![
            IpxeOsParameter {
                name: "base_url".to_string(),
                value: "http://pxe.local".to_string(),
            },
            IpxeOsParameter {
                name: "console".to_string(),
                value: "ttyS0,115200".to_string(),
            },
            IpxeOsParameter {
                name: "console".to_string(),
                value: "ttyS0,115200".to_string(),
            },
            IpxeOsParameter {
                name: "extra_reserved".to_string(),
                value: "value".to_string(),
            },
        ];

        let result = renderer.render(&ipxeos, &reserved_params);
        assert!(matches!(
            result,
            Err(IpxeOsError::UnexpectedReservedParameter(_))
        ));
    }

    #[test]
    fn test_unreplaced_placeholders() {
        let renderer = DefaultIpxeOsRenderer::new();
        let mut ipxeos = create_test_ipxeos();
        // Remove the required parameter to cause unreplaced placeholder
        ipxeos.parameters.clear();
        ipxeos.hash = renderer.hash(&ipxeos);

        // Validation will fail first, but let's test the unreplaced check by using a template
        // that doesn't require this param
        ipxeos.ipxe_template_name = "qcow-image".to_string();
        ipxeos.parameters = vec![]; // Missing image_url
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
        // Will fail on required parameter validation first
        assert!(result.is_err());
    }

    #[test]
    fn test_extra_parameter_name_reserved() {
        let renderer = DefaultIpxeOsRenderer::new();
        let mut ipxeos = create_test_ipxeos();

        // Try to use "extra" as a parameter name (should be rejected)
        ipxeos.parameters.push(IpxeOsParameter {
            name: "extra".to_string(),
            value: "some_value".to_string(),
        });
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
        assert!(matches!(
            result,
            Err(IpxeOsError::ReservedParameterFound(_))
        ));
        
        // Verify error message mentions "extra"
        if let Err(IpxeOsError::ReservedParameterFound(msg)) = result {
            assert!(msg.contains("extra"));
        }
    }

    #[test]
    fn test_extra_artifact_name_reserved() {
        let renderer = DefaultIpxeOsRenderer::new();
        let mut ipxeos = create_test_ipxeos();

        // Try to use "extra" as an artifact name (should be rejected)
        ipxeos.artifacts.push(IpxeOsArtifact {
            name: "extra".to_string(),
            url: "http://example.com/extra".to_string(),
            sha: None,
            auth_type: None,
            auth_token: None,
            cache_strategy: ArtifactCacheStrategy::CacheAsNeeded,
            local_url: None,
        });
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
        assert!(matches!(
            result,
            Err(IpxeOsError::ReservedParameterFound(_))
        ));
        
        // Verify error message mentions "extra"
        if let Err(IpxeOsError::ReservedParameterFound(msg)) = result {
            assert!(msg.contains("extra"));
        }
    }

    #[test]
    fn test_extra_case_insensitive_rejected() {
        // All case variations of "extra" should be rejected (case-insensitive)
        let renderer = DefaultIpxeOsRenderer::new();
        let mut ipxeos = create_test_ipxeos();

        // "Extra" (capitalized) should also be rejected (case-insensitive)
        ipxeos.parameters.push(IpxeOsParameter {
            name: "Extra".to_string(),
            value: "not_allowed".to_string(),
        });
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
        assert!(matches!(
            result,
            Err(IpxeOsError::ReservedParameterFound(_))
        ));
        
        // Verify error message mentions the parameter
        if let Err(IpxeOsError::ReservedParameterFound(msg)) = result {
            assert!(msg.contains("Extra") || msg.contains("extra"));
        }
    }

    #[test]
    fn test_case_preserved_in_extra() {
        // Original case should be preserved in {{extra}} for non-reserved parameters
        let renderer = DefaultIpxeOsRenderer::new();
        let mut ipxeos = create_test_ipxeos();

        // Add parameters with mixed case (not "extra")
        ipxeos.parameters.push(IpxeOsParameter {
            name: "MyCustomParam".to_string(),
            value: "value1".to_string(),
        });
        ipxeos.parameters.push(IpxeOsParameter {
            name: "AnotherParam".to_string(),
            value: "value2".to_string(),
        });
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
        // Original case should be preserved in {{extra}}
        assert!(script.contains("MyCustomParam=value1"));
        assert!(script.contains("AnotherParam=value2"));
        // Lowercase versions should NOT appear
        assert!(!script.contains("mycustomparam="));
        assert!(!script.contains("anotherparam="));
    }

    #[test]
    fn test_case_insensitive_parameter_matching() {
        // Parameter names should match case-insensitively
        let renderer = DefaultIpxeOsRenderer::new();
        
        let ipxeos = IpxeOs {
            name: "Test".to_string(),
            description: None,
            hash: "".to_string(),
            tenant_id: None,
            ipxe_template_name: "qcow-image".to_string(),
            parameters: vec![
                IpxeOsParameter {
                    name: "IMAGE_URL".to_string(),  // Uppercase
                    value: "http://example.com/image.qcow2".to_string(),
                },
            ],
            artifacts: vec![],
        };
        
        let mut ipxeos_with_hash = ipxeos.clone();
        ipxeos_with_hash.hash = renderer.hash(&ipxeos);

        let reserved_params = vec![
            IpxeOsParameter {
                name: "BASE_URL".to_string(),  // Uppercase
                value: "http://pxe.local".to_string(),
            },
            IpxeOsParameter {
                name: "CONSOLE".to_string(),  // Uppercase
                value: "ttyS0,115200".to_string(),
            },
        ];

        let result = renderer.render(&ipxeos_with_hash, &reserved_params);
        assert!(result.is_ok());
        
        let script = result.unwrap();
        // Should match case-insensitively and render correctly
        assert!(script.contains("http://pxe.local"));
        assert!(script.contains("ttyS0,115200"));
        assert!(script.contains("http://example.com/image.qcow2"));
    }

    #[test]
    fn test_case_insensitive_hash_equivalence() {
        // Different cases of same parameter name should produce same hash
        let renderer = DefaultIpxeOsRenderer::new();
        
        let ipxeos1 = IpxeOs {
            name: "Test".to_string(),
            description: None,
            hash: "".to_string(),
            tenant_id: None,
            ipxe_template_name: "qcow-image".to_string(),
            parameters: vec![
                IpxeOsParameter {
                    name: "image_url".to_string(),  // lowercase
                    value: "http://example.com/image.qcow2".to_string(),
                },
            ],
            artifacts: vec![],
        };
        
        let ipxeos2 = IpxeOs {
            name: "Test".to_string(),
            description: None,
            hash: "".to_string(),
            tenant_id: None,
            ipxe_template_name: "qcow-image".to_string(),
            parameters: vec![
                IpxeOsParameter {
                    name: "IMAGE_URL".to_string(),  // UPPERCASE
                    value: "http://example.com/image.qcow2".to_string(),
                },
            ],
            artifacts: vec![],
        };

        let hash1 = renderer.hash(&ipxeos1);
        let hash2 = renderer.hash(&ipxeos2);
        
        // Hashes should match (case-insensitive)
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_parameter_and_artifact_same_name_in_required() {
        // If required_params has "foo" and we have both parameter and artifact named "foo",
        // parameter should be consumed first (artifacts only consumed by required_artifacts)
        let renderer = DefaultIpxeOsRenderer::new();
        
        let ipxeos = IpxeOs {
            name: "Test".to_string(),
            description: None,
            hash: "".to_string(),
            tenant_id: None,
            ipxe_template_name: "qcow-image".to_string(),
            parameters: vec![
                IpxeOsParameter {
                    name: "image_url".to_string(),
                    value: "param_value".to_string(),
                },
            ],
            artifacts: vec![
                IpxeOsArtifact {
                    name: "image_url".to_string(),  // Same name as parameter
                    url: "artifact_url".to_string(),
                    sha: None,
                    auth_type: None,
                    auth_token: None,
                    cache_strategy: ArtifactCacheStrategy::CacheAsNeeded,
                    local_url: None,
                },
            ],
        };
        
        let mut ipxeos_with_hash = ipxeos.clone();
        ipxeos_with_hash.hash = renderer.hash(&ipxeos);

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

        let result = renderer.render(&ipxeos_with_hash, &reserved_params);
        assert!(result.is_ok());
        
        let script = result.unwrap();
        // Parameter value should be used (not artifact URL) since required_params consumes parameters
        assert!(script.contains("image_url=param_value"));
        assert!(!script.contains("artifact_url"));
    }

    #[test]
    fn test_duplicate_parameters_occurrence_based() {
        let renderer = DefaultIpxeOsRenderer::new();
        let mut ipxeos = create_test_ipxeos();

        // Add duplicate parameter - first consumed by required_params, second goes to {{extra}}
        ipxeos.parameters.push(IpxeOsParameter {
            name: "image_url".to_string(),
            value: "http://example.com/duplicate.qcow2".to_string(),
        });

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
        // First occurrence consumed by {{image_url}} placeholder
        assert!(script.contains("image_url=http://example.com/image.qcow2"));
        // Second occurrence goes to {{extra}}
        assert!(script.contains("image_url=http://example.com/duplicate.qcow2"));
    }

    #[test]
    fn test_duplicate_parameters_in_hash() {
        let renderer = DefaultIpxeOsRenderer::new();

        let ipxeos1 = IpxeOs {
            name: "Test".to_string(),
            description: None,
            hash: "".to_string(),
            tenant_id: None,
            ipxe_template_name: "qcow-image".to_string(),
            parameters: vec![IpxeOsParameter {
                name: "image_url".to_string(),
                value: "http://example.com/image.qcow2".to_string(),
            }],
            artifacts: vec![],
        };

        let mut ipxeos2 = ipxeos1.clone();
        ipxeos2.parameters.push(IpxeOsParameter {
            name: "image_url".to_string(),
            value: "http://example.com/duplicate.qcow2".to_string(),
        });

        let hash1 = renderer.hash(&ipxeos1);
        let hash2 = renderer.hash(&ipxeos2);

        // Hashes should be different (duplicates affect hash)
        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_hash_parameter_order_determinism() {
        let renderer = DefaultIpxeOsRenderer::new();

        let ipxeos1 = IpxeOs {
            name: "Test".to_string(),
            description: None,
            hash: "".to_string(),
            tenant_id: None,
            ipxe_template_name: "qcow-image".to_string(),
            parameters: vec![
                IpxeOsParameter {
                    name: "image_url".to_string(),
                    value: "http://example.com/image.qcow2".to_string(),
                },
                IpxeOsParameter {
                    name: "extra1".to_string(),
                    value: "value1".to_string(),
                },
                IpxeOsParameter {
                    name: "extra2".to_string(),
                    value: "value2".to_string(),
                },
            ],
            artifacts: vec![],
        };

        let ipxeos2 = IpxeOs {
            name: "Test".to_string(),
            description: None,
            hash: "".to_string(),
            tenant_id: None,
            ipxe_template_name: "qcow-image".to_string(),
            parameters: vec![
                IpxeOsParameter {
                    name: "extra2".to_string(),
                    value: "value2".to_string(),
                },
                IpxeOsParameter {
                    name: "image_url".to_string(),
                    value: "http://example.com/image.qcow2".to_string(),
                },
                IpxeOsParameter {
                    name: "extra1".to_string(),
                    value: "value1".to_string(),
                },
            ],
            artifacts: vec![],
        };

        let hash1 = renderer.hash(&ipxeos1);
        let hash2 = renderer.hash(&ipxeos2);

        // Hashes should be same (order-independent)
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_hash_artifact_order_determinism() {
        let renderer = DefaultIpxeOsRenderer::new();

        let ipxeos1 = IpxeOs {
            name: "Test".to_string(),
            description: None,
            hash: "".to_string(),
            tenant_id: None,
            ipxe_template_name: "ubuntu-autoinstall".to_string(),
            parameters: vec![IpxeOsParameter {
                name: "install_iso".to_string(),
                value: "http://example.com/ubuntu.iso".to_string(),
            }],
            artifacts: vec![
                IpxeOsArtifact {
                    name: "kernel".to_string(),
                    url: "http://example.com/kernel".to_string(),
                    sha: Some("sha256:kernel123".to_string()),
                    auth_type: None,
                    auth_token: None,
                    cache_strategy: ArtifactCacheStrategy::CacheAsNeeded,
                    local_url: None,
                },
                IpxeOsArtifact {
                    name: "initrd".to_string(),
                    url: "http://example.com/initrd".to_string(),
                    sha: Some("sha256:initrd456".to_string()),
                    auth_type: None,
                    auth_token: None,
                    cache_strategy: ArtifactCacheStrategy::CacheAsNeeded,
                    local_url: None,
                },
            ],
        };

        let ipxeos2 = IpxeOs {
            name: "Test".to_string(),
            description: None,
            hash: "".to_string(),
            tenant_id: None,
            ipxe_template_name: "ubuntu-autoinstall".to_string(),
            parameters: vec![IpxeOsParameter {
                name: "install_iso".to_string(),
                value: "http://example.com/ubuntu.iso".to_string(),
            }],
            artifacts: vec![
                IpxeOsArtifact {
                    name: "initrd".to_string(),
                    url: "http://example.com/initrd".to_string(),
                    sha: Some("sha256:initrd456".to_string()),
                    auth_type: None,
                    auth_token: None,
                    cache_strategy: ArtifactCacheStrategy::CacheAsNeeded,
                    local_url: None,
                },
                IpxeOsArtifact {
                    name: "kernel".to_string(),
                    url: "http://example.com/kernel".to_string(),
                    sha: Some("sha256:kernel123".to_string()),
                    auth_type: None,
                    auth_token: None,
                    cache_strategy: ArtifactCacheStrategy::CacheAsNeeded,
                    local_url: None,
                },
            ],
        };

        let hash1 = renderer.hash(&ipxeos1);
        let hash2 = renderer.hash(&ipxeos2);

        // Hashes should be same (artifact order independent)
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_hash_excludes_cache_strategy() {
        let renderer = DefaultIpxeOsRenderer::new();

        let ipxeos1 = IpxeOs {
            name: "Test".to_string(),
            description: None,
            hash: "".to_string(),
            tenant_id: None,
            ipxe_template_name: "ubuntu-autoinstall".to_string(),
            parameters: vec![IpxeOsParameter {
                name: "install_iso".to_string(),
                value: "http://example.com/ubuntu.iso".to_string(),
            }],
            artifacts: vec![IpxeOsArtifact {
                name: "kernel".to_string(),
                url: "http://example.com/kernel".to_string(),
                sha: Some("sha256:kernel123".to_string()),
                auth_type: None,
                auth_token: None,
                cache_strategy: ArtifactCacheStrategy::CacheAsNeeded,
                local_url: None,
            }],
        };

        let mut ipxeos2 = ipxeos1.clone();
        ipxeos2.artifacts[0].cache_strategy = ArtifactCacheStrategy::RemoteOnly;

        let hash1 = renderer.hash(&ipxeos1);
        let hash2 = renderer.hash(&ipxeos2);

        // Hashes should be same (cache_strategy excluded)
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_hash_excludes_local_url() {
        let renderer = DefaultIpxeOsRenderer::new();

        let ipxeos1 = IpxeOs {
            name: "Test".to_string(),
            description: None,
            hash: "".to_string(),
            tenant_id: None,
            ipxe_template_name: "ubuntu-autoinstall".to_string(),
            parameters: vec![IpxeOsParameter {
                name: "install_iso".to_string(),
                value: "http://example.com/ubuntu.iso".to_string(),
            }],
            artifacts: vec![IpxeOsArtifact {
                name: "kernel".to_string(),
                url: "http://example.com/kernel".to_string(),
                sha: Some("sha256:kernel123".to_string()),
                auth_type: None,
                auth_token: None,
                cache_strategy: ArtifactCacheStrategy::CacheAsNeeded,
                local_url: None,
            }],
        };

        let mut ipxeos2 = ipxeos1.clone();
        ipxeos2.artifacts[0].local_url = Some("http://local-cache/kernel".to_string());

        let hash1 = renderer.hash(&ipxeos1);
        let hash2 = renderer.hash(&ipxeos2);

        // Hashes should be same (local_url excluded)
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_hash_repeatability() {
        let renderer = DefaultIpxeOsRenderer::new();

        let ipxeos = IpxeOs {
            name: "Test".to_string(),
            description: Some("Test OS".to_string()),
            hash: "".to_string(),
            tenant_id: Some("tenant-123".to_string()),
            ipxe_template_name: "qcow-image".to_string(),
            parameters: vec![
                IpxeOsParameter {
                    name: "image_url".to_string(),
                    value: "http://example.com/image.qcow2".to_string(),
                },
                IpxeOsParameter {
                    name: "extra1".to_string(),
                    value: "value1".to_string(),
                },
            ],
            artifacts: vec![IpxeOsArtifact {
                name: "test".to_string(),
                url: "http://example.com/test".to_string(),
                sha: Some("sha256:test123".to_string()),
                auth_type: Some("Bearer".to_string()),
                auth_token: Some("token".to_string()),
                cache_strategy: ArtifactCacheStrategy::CacheAsNeeded,
                local_url: None,
            }],
        };

        let hash1 = renderer.hash(&ipxeos);
        let hash2 = renderer.hash(&ipxeos);
        let hash3 = renderer.hash(&ipxeos);

        // All hashes should be identical
        assert_eq!(hash1, hash2);
        assert_eq!(hash2, hash3);
    }

    #[test]
    fn test_double_space_cleanup() {
        let renderer = DefaultIpxeOsRenderer::new();
        let mut ipxeos = create_test_ipxeos();

        // Add empty optional parameters that would create double spaces
        ipxeos.parameters.push(IpxeOsParameter {
            name: "empty1".to_string(),
            value: "".to_string(),
        });
        ipxeos.parameters.push(IpxeOsParameter {
            name: "opt1".to_string(),
            value: "value1".to_string(),
        });

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
        // Verify no double spaces exist
        assert!(!script.contains("  "));
    }

    #[test]
    fn test_empty_optional_parameters_not_in_extra() {
        let renderer = DefaultIpxeOsRenderer::new();
        let mut ipxeos = create_test_ipxeos();

        // Add empty optional parameter
        ipxeos.parameters.push(IpxeOsParameter {
            name: "empty_opt".to_string(),
            value: "".to_string(),
        });
        // Add non-empty optional parameter
        ipxeos.parameters.push(IpxeOsParameter {
            name: "valid_opt".to_string(),
            value: "value".to_string(),
        });

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
        // Empty parameter should not appear
        assert!(!script.contains("empty_opt"));
        // Non-empty parameter should appear
        assert!(script.contains("valid_opt=value"));
    }

    #[test]
    fn test_fabricate_local_urls_comprehensive() {
        let renderer = DefaultIpxeOsRenderer::new();

        let ipxeos = IpxeOs {
            name: "Test".to_string(),
            description: None,
            hash: "test-hash".to_string(),
            tenant_id: None,
            ipxe_template_name: "ubuntu-autoinstall".to_string(),
            parameters: vec![IpxeOsParameter {
                name: "install_iso".to_string(),
                value: "http://example.com/ubuntu.iso".to_string(),
            }],
            artifacts: vec![
                // Artifact with SHA - should generate hash of SHA
                IpxeOsArtifact {
                    name: "kernel".to_string(),
                    url: "http://example.com/kernel".to_string(),
                    sha: Some("sha256:test123".to_string()),
                    auth_type: None,
                    auth_token: None,
                    cache_strategy: ArtifactCacheStrategy::CacheAsNeeded,
                    local_url: None,
                },
                // Artifact without SHA - should generate hash of artifact record
                IpxeOsArtifact {
                    name: "initrd".to_string(),
                    url: "http://example.com/initrd".to_string(),
                    sha: None,
                    auth_type: None,
                    auth_token: None,
                    cache_strategy: ArtifactCacheStrategy::CacheAsNeeded,
                    local_url: None,
                },
                // RemoteOnly - should skip
                IpxeOsArtifact {
                    name: "remote".to_string(),
                    url: "http://example.com/remote".to_string(),
                    sha: Some("sha256:remote".to_string()),
                    auth_type: None,
                    auth_token: None,
                    cache_strategy: ArtifactCacheStrategy::RemoteOnly,
                    local_url: None,
                },
                // Has iPXE variable - should skip
                IpxeOsArtifact {
                    name: "local".to_string(),
                    url: "${base-url}/local.img".to_string(),
                    sha: Some("sha256:local".to_string()),
                    auth_type: None,
                    auth_token: None,
                    cache_strategy: ArtifactCacheStrategy::CacheAsNeeded,
                    local_url: None,
                },
            ],
        };

        let result = renderer.fabricate_local_urls(&ipxeos);

        // First artifact should have local_url using sha field directly
        assert!(result.artifacts[0].local_url.is_some());
        let url1 = result.artifacts[0].local_url.as_ref().unwrap();
        assert_eq!(url1, "${base_url}/sha256:test123");

        // Second artifact (no sha) should have local_url with generated 64-char hash
        assert!(result.artifacts[1].local_url.is_some());
        let url2 = result.artifacts[1].local_url.as_ref().unwrap();
        assert!(url2.starts_with("${base_url}/"));
        let hash2 = url2.strip_prefix("${base_url}/").unwrap();
        assert_eq!(hash2.len(), 64); // Generated SHA256 hex
        assert_ne!(url1, url2); // Different URLs

        // Third artifact (RemoteOnly) should not have local_url
        assert!(result.artifacts[2].local_url.is_none());

        // Fourth artifact (has variable) should not have local_url
        assert!(result.artifacts[3].local_url.is_none());
    }

    #[test]
    fn test_fabricate_local_urls_deterministic() {
        let renderer = DefaultIpxeOsRenderer::new();

        let ipxeos = IpxeOs {
            name: "Test".to_string(),
            description: None,
            hash: "test-hash".to_string(),
            tenant_id: None,
            ipxe_template_name: "ubuntu-autoinstall".to_string(),
            parameters: vec![IpxeOsParameter {
                name: "install_iso".to_string(),
                value: "http://example.com/ubuntu.iso".to_string(),
            }],
            artifacts: vec![IpxeOsArtifact {
                name: "kernel".to_string(),
                url: "http://example.com/kernel".to_string(),
                sha: Some("sha256:test123".to_string()),
                auth_type: None,
                auth_token: None,
                cache_strategy: ArtifactCacheStrategy::CacheAsNeeded,
                local_url: None,
            }],
        };

        let result1 = renderer.fabricate_local_urls(&ipxeos);
        let result2 = renderer.fabricate_local_urls(&ipxeos);

        // Should generate same URL both times
        assert_eq!(
            result1.artifacts[0].local_url,
            result2.artifacts[0].local_url
        );
    }

    #[test]
    fn test_render_whoami_static_template() {
        let renderer = DefaultIpxeOsRenderer::new();

        // Get the whoami template
        let template = renderer.get_template("whoami").expect("whoami template should exist");

        // whoami template is static - no parameters, no artifacts, no placeholders
        let mut ipxeos = IpxeOs {
            name: "WhoAmI".to_string(),
            description: Some("Static whoami script".to_string()),
            hash: String::new(),
            tenant_id: None,
            ipxe_template_name: "whoami".to_string(),
            parameters: vec![],
            artifacts: vec![],
        };

        // Compute and set the correct hash for validation
        ipxeos.hash = renderer.hash(&ipxeos);

        // No reserved params needed
        let reserved_params = vec![];

        let result = renderer.render(&ipxeos, &reserved_params);
        assert!(result.is_ok(), "Render failed: {:?}", result.err());
        
        let rendered_script = result.unwrap();
        
        // Compute checksum of rendered script
        let mut hasher_rendered = Sha256::new();
        hasher_rendered.update(rendered_script.as_bytes());
        let rendered_hash = format!("{:x}", hasher_rendered.finalize());
        
        // Compute checksum of template text (normalized - trailing spaces removed per line)
        let normalized_template = template.template.lines()
            .map(|line| line.trim_end())
            .collect::<Vec<_>>()
            .join("\n");
        let mut hasher_template = Sha256::new();
        hasher_template.update(normalized_template.as_bytes());
        let template_hash = format!("{:x}", hasher_template.finalize());
        
        // Checksums should match - template rendered as-is with no alterations
        assert_eq!(rendered_hash, template_hash, 
            "Rendered script should match template exactly (static template with no placeholders)");
    }
}
