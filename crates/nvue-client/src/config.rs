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
