#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
#[serde(transparent)]
pub struct NvueConfig {
    // FIXME: Replace this with a more strongly typed inner representation
    config_json: serde_json::Value,
}

impl NvueConfig {
    pub fn from_yaml(yaml: &str) -> Result<Self, serde_yaml::Error> {
        serde_yaml::from_str(yaml)
    }

    pub fn remove_rev_id(&mut self) {
        if let serde_json::Value::Object(config_root) = &mut self.config_json
            && let Some(header_value) = config_root.get_mut("header")
            && let serde_json::Value::Object(header_object) = header_value
        {
            let _ = header_object.remove("rev-id");
        }
    }

    /// Extract the value under the `set` key from the top-level list structure
    /// produced by the NVUE startup templates (i.e. `[{header: ...}, {set: ...}]`).
    /// Returns `None` if the config is not in that list form.
    pub fn extract_set_payload(&self) -> Option<Self> {
        if let serde_json::Value::Array(arr) = &self.config_json {
            for item in arr {
                if let serde_json::Value::Object(map) = item {
                    if let Some(set_value) = map.get("set") {
                        return Some(Self {
                            config_json: set_value.clone(),
                        });
                    }
                }
            }
        }
        None
    }

    /// Remove any interfaces whose names start with `pf0dpu` from the config.
    /// These interfaces lack a `type` field, which the NVUE REST API rejects;
    /// they are left to be configured by other means.
    pub fn remove_pf0dpu_interfaces(&mut self) {
        if let serde_json::Value::Object(root) = &mut self.config_json
            && let Some(serde_json::Value::Object(ifaces)) = root.get_mut("interface")
        {
            ifaces.retain(|key, _| !key.starts_with("pf0dpu"));
        }
    }
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
#[serde(transparent)]
pub struct NvueRevision {
    // FIXME: Replace this with a more strongly typed inner representation
    revision_json: serde_json::Value,
}

impl NvueRevision {
    pub fn get_revision_id(&self) -> Option<String> {
        dbg!(self);
        if let serde_json::Value::Object(map) = &self.revision_json
            && map.len() == 1
        {
            map.keys().nth(0).cloned()
        } else {
            None
        }
    }
}
