#[derive(Debug, Deserialize, Clone)]
pub struct FirmwareCurrent {
    #[serde(rename = "VersionString")]
    pub version: String,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "PascalCase")]
pub struct Firmware {
    pub current: FirmwareCurrent,
}

#[derive(Debug, Deserialize, Clone)]
pub struct Href {
    pub href: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct ExtRef {
    pub extref: String,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(untagged, rename_all = "PascalCase")]
pub enum LinkType {
    SelfLink {
        #[serde(rename = "self")]
        self_url: Href,
    },
    HpLink {
        fast_power_meter: Href,
        federated_group_capping: Href,
        power_meter: Href,
    },
    OemHpLink {
        active_health_system: Href,
        date_time_service: Href,
        embedded_media_service: Href,
        federation_dispatch: ExtRef,
        federation_groups: Href,
        federation_peers: Href,
        license_service: Href,
        security_service: Href,
        update_service: Href,
        #[serde(rename = "VSPLogLocation")]
        vsp_log_location: ExtRef,
    },
    SerdeJson {
        #[serde(rename = "links")]
        links: serde_json::Value,
    },
    EnclosuresLinks {
        member: Vec<Href>,
        #[serde(rename = "self")]
        self_url: Href,
    },
    ManagerLink {
        #[serde(rename = "EthernetNICs")]
        ethernet_nics: Href,
        logs: Href,
        manager_for_chassis: Vec<Href>,
        manager_for_servers: Vec<Href>,
        network_service: Href,
        virtual_media: Href,
        #[serde(rename = "self")]
        self_url: Href,
    },
    StorageLink {
        logical_drives: Href,
        physical_drives: Href,
        storage_enclosures: Href,
        unconfigured_drives: Href,
        #[serde(rename = "self")]
        self_url: Href,
    },
}

#[derive(Debug, Deserialize, Clone)]
pub struct ODataLinks {
    #[serde(rename = "@odata.context")]
    pub odata_context: String,
    #[serde(rename = "@odata.id")]
    pub odata_id: String,
    #[serde(rename = "@odata.type")]
    pub odata_type: String,
    #[serde(rename = "links")]
    pub links: LinkType,
}

#[derive(Debug, Deserialize, Clone)]
pub struct ODataId {
    #[serde(rename = "@odata.id")]
    pub odata_id: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct ODataContext {
    #[serde(rename = "@odata.context")]
    pub odata_context: String,
    #[serde(rename = "links")]
    pub links: LinkType,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "PascalCase")]
pub struct AllStatus {
    pub health: String,
    pub state: String,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "PascalCase")]
pub struct SomeStatus {
    pub health: Option<String>,
    pub state: String,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "PascalCase")]
pub struct HpType {
    #[serde(rename = "@odata.type")]
    pub odata_type: String,
    #[serde(rename = "Type")]
    pub hp_type: String,
}

pub trait Status {
    fn health(&self) -> String;
    fn state(&self) -> String;
}

impl Status for SomeStatus {
    fn health(&self) -> String {
        match &self.health {
            Some(s) => s.clone(),
            None => "OK".to_string(),
        }
    }
    fn state(&self) -> String {
        self.state.clone()
    }
}

impl Status for AllStatus {
    fn health(&self) -> String {
        self.health.clone()
    }
    fn state(&self) -> String {
        self.state.clone()
    }
}

pub trait StatusVec {
    fn get_vec(&self) -> Vec<Box<dyn Status>>;
}
