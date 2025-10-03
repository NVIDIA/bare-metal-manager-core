use crate::cfg::file::{Firmware, FirmwareComponentType};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Firmware versions this carbide instance wants to install onto hosts
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "PascalCase")]
pub struct DesiredFirmwareVersions {
    /// Parsed versions, serializtion override means it will always be sorted
    #[serde(default, serialize_with = "utils::ordered_map")]
    pub versions: HashMap<FirmwareComponentType, String>,
}

impl From<Firmware> for DesiredFirmwareVersions {
    fn from(value: Firmware) -> Self {
        // Using a BTreeMap instead of a hash means that this will be sorted by the key
        let mut versions: DesiredFirmwareVersions = Default::default();
        for (component_type, component) in value.components {
            for firmware in component.known_firmware {
                if firmware.default {
                    versions.versions.insert(component_type, firmware.version);
                    break;
                }
            }
        }
        versions
    }
}
