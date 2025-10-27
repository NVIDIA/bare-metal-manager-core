use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, Serialize, Clone, PartialEq, Eq)]
pub struct ResourcePoolDef {
    #[serde(default)]
    pub ranges: Vec<Range>,
    #[serde(default)]
    pub prefix: Option<String>,
    #[serde(rename = "type")]
    pub pool_type: ResourcePoolType,
}

#[derive(Debug, Deserialize, Serialize, Clone, PartialEq, Eq)]
pub struct Range {
    pub start: String,
    pub end: String,
}

#[derive(Debug, Deserialize, Serialize, Copy, Clone, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ResourcePoolType {
    Ipv4,
    Integer,
}
