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

use model::rack_type::{
    RackCapabilitiesSet, RackCapabilityCompute, RackCapabilityPowerShelf, RackCapabilitySwitch,
    RackHardwareClass, RackHardwareTopology, RackHardwareType, RackProfile,
};

use crate as rpc;
use crate::errors::RpcDataConversionError;

impl From<RackHardwareType> for rpc::common::RackHardwareType {
    fn from(value: RackHardwareType) -> Self {
        rpc::common::RackHardwareType { value: value.0 }
    }
}

impl From<rpc::common::RackHardwareType> for RackHardwareType {
    fn from(value: rpc::common::RackHardwareType) -> Self {
        RackHardwareType(value.value)
    }
}

impl From<RackHardwareTopology> for rpc::forge::RackHardwareTopology {
    fn from(value: RackHardwareTopology) -> Self {
        match value {
            RackHardwareTopology::Gb200Nvl36r1C2g4Topology => {
                rpc::forge::RackHardwareTopology::Gb200Nvl36r1C2g4
            }
            RackHardwareTopology::Gb300Nvl36r1C2g4Topology => {
                rpc::forge::RackHardwareTopology::Gb300Nvl36r1C2g4
            }
            RackHardwareTopology::Gb200Nvl72r1C2g4Topology => {
                rpc::forge::RackHardwareTopology::Gb200Nvl72r1C2g4
            }
            RackHardwareTopology::Gb300Nvl72r1C2g4Topology => {
                rpc::forge::RackHardwareTopology::Gb300Nvl72r1C2g4
            }
            RackHardwareTopology::VrNvl8r1C2g4RtfTopology => {
                rpc::forge::RackHardwareTopology::VrNvl8r1C2g4Rtf
            }
            RackHardwareTopology::VrNvl72r1C2g4Topology => {
                rpc::forge::RackHardwareTopology::VrNvl72r1C2g4
            }
        }
    }
}

impl TryFrom<rpc::forge::RackHardwareTopology> for RackHardwareTopology {
    type Error = RpcDataConversionError;

    fn try_from(value: rpc::forge::RackHardwareTopology) -> Result<Self, Self::Error> {
        match value {
            rpc::forge::RackHardwareTopology::Gb200Nvl36r1C2g4 => {
                Ok(RackHardwareTopology::Gb200Nvl36r1C2g4Topology)
            }
            rpc::forge::RackHardwareTopology::Gb300Nvl36r1C2g4 => {
                Ok(RackHardwareTopology::Gb300Nvl36r1C2g4Topology)
            }
            rpc::forge::RackHardwareTopology::Gb200Nvl72r1C2g4 => {
                Ok(RackHardwareTopology::Gb200Nvl72r1C2g4Topology)
            }
            rpc::forge::RackHardwareTopology::Gb300Nvl72r1C2g4 => {
                Ok(RackHardwareTopology::Gb300Nvl72r1C2g4Topology)
            }
            rpc::forge::RackHardwareTopology::VrNvl8r1C2g4Rtf => {
                Ok(RackHardwareTopology::VrNvl8r1C2g4RtfTopology)
            }
            rpc::forge::RackHardwareTopology::VrNvl72r1C2g4 => {
                Ok(RackHardwareTopology::VrNvl72r1C2g4Topology)
            }
            rpc::forge::RackHardwareTopology::Unspecified => {
                Err(RpcDataConversionError::InvalidArgument(
                    "unspecified rack hardware topology".to_string(),
                ))
            }
        }
    }
}

impl From<RackHardwareClass> for rpc::forge::RackHardwareClass {
    fn from(value: RackHardwareClass) -> Self {
        match value {
            RackHardwareClass::Dev => rpc::forge::RackHardwareClass::Dev,
            RackHardwareClass::Prod => rpc::forge::RackHardwareClass::Prod,
        }
    }
}

impl TryFrom<rpc::forge::RackHardwareClass> for RackHardwareClass {
    type Error = RpcDataConversionError;

    fn try_from(value: rpc::forge::RackHardwareClass) -> Result<Self, Self::Error> {
        match value {
            rpc::forge::RackHardwareClass::Dev => Ok(RackHardwareClass::Dev),
            rpc::forge::RackHardwareClass::Prod => Ok(RackHardwareClass::Prod),
            rpc::forge::RackHardwareClass::Unspecified => {
                Err(RpcDataConversionError::InvalidArgument(
                    "unspecified rack hardware class".to_string(),
                ))
            }
        }
    }
}

impl From<&RackCapabilityCompute> for rpc::forge::RackCapabilityCompute {
    fn from(value: &RackCapabilityCompute) -> Self {
        rpc::forge::RackCapabilityCompute {
            name: value.name.clone(),
            count: value.count,
            vendor: value.vendor.clone(),
            slot_ids: value.slot_ids.clone().unwrap_or_default(),
        }
    }
}

impl From<&RackCapabilitySwitch> for rpc::forge::RackCapabilitySwitch {
    fn from(value: &RackCapabilitySwitch) -> Self {
        rpc::forge::RackCapabilitySwitch {
            name: value.name.clone(),
            count: value.count,
            vendor: value.vendor.clone(),
            slot_ids: value.slot_ids.clone().unwrap_or_default(),
        }
    }
}

impl From<&RackCapabilityPowerShelf> for rpc::forge::RackCapabilityPowerShelf {
    fn from(value: &RackCapabilityPowerShelf) -> Self {
        rpc::forge::RackCapabilityPowerShelf {
            name: value.name.clone(),
            count: value.count,
            vendor: value.vendor.clone(),
            slot_ids: value.slot_ids.clone().unwrap_or_default(),
        }
    }
}

impl From<&RackCapabilitiesSet> for rpc::forge::RackCapabilitiesSet {
    fn from(value: &RackCapabilitiesSet) -> Self {
        rpc::forge::RackCapabilitiesSet {
            compute: Some((&value.compute).into()),
            switch: Some((&value.switch).into()),
            power_shelf: Some((&value.power_shelf).into()),
        }
    }
}

impl From<&RackProfile> for rpc::forge::RackProfile {
    fn from(value: &RackProfile) -> Self {
        rpc::forge::RackProfile {
            rack_hardware_type: value
                .rack_hardware_type
                .as_ref()
                .map(|t| rpc::common::RackHardwareType::from(t.clone())),
            rack_hardware_topology: value
                .rack_hardware_topology
                .map(|t| rpc::forge::RackHardwareTopology::from(t) as i32)
                .unwrap_or(rpc::forge::RackHardwareTopology::Unspecified as i32),
            rack_hardware_class: value
                .rack_hardware_class
                .map(|c| rpc::forge::RackHardwareClass::from(c) as i32)
                .unwrap_or(rpc::forge::RackHardwareClass::Unspecified as i32),
            capabilities: Some((&value.rack_capabilities).into()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    // Proto conversion tests.

    #[test]
    fn test_rack_hardware_topology_proto_round_trip() {
        let cases = [
            (
                RackHardwareTopology::Gb200Nvl36r1C2g4Topology,
                rpc::forge::RackHardwareTopology::Gb200Nvl36r1C2g4,
            ),
            (
                RackHardwareTopology::Gb300Nvl36r1C2g4Topology,
                rpc::forge::RackHardwareTopology::Gb300Nvl36r1C2g4,
            ),
            (
                RackHardwareTopology::Gb200Nvl72r1C2g4Topology,
                rpc::forge::RackHardwareTopology::Gb200Nvl72r1C2g4,
            ),
            (
                RackHardwareTopology::Gb300Nvl72r1C2g4Topology,
                rpc::forge::RackHardwareTopology::Gb300Nvl72r1C2g4,
            ),
            (
                RackHardwareTopology::VrNvl8r1C2g4RtfTopology,
                rpc::forge::RackHardwareTopology::VrNvl8r1C2g4Rtf,
            ),
            (
                RackHardwareTopology::VrNvl72r1C2g4Topology,
                rpc::forge::RackHardwareTopology::VrNvl72r1C2g4,
            ),
        ];
        for (model, proto) in cases {
            let converted: rpc::forge::RackHardwareTopology = model.into();
            assert_eq!(converted, proto);
            let back: RackHardwareTopology = proto.try_into().unwrap();
            assert_eq!(back, model);
        }
    }

    #[test]
    fn test_rack_hardware_topology_proto_unspecified_errors() {
        let result = RackHardwareTopology::try_from(rpc::forge::RackHardwareTopology::Unspecified);
        assert!(result.is_err());
    }

    #[test]
    fn test_rack_hardware_class_proto_round_trip() {
        let cases = [
            (RackHardwareClass::Dev, rpc::forge::RackHardwareClass::Dev),
            (RackHardwareClass::Prod, rpc::forge::RackHardwareClass::Prod),
        ];
        for (model, proto) in cases {
            let converted: rpc::forge::RackHardwareClass = model.into();
            assert_eq!(converted, proto);
            let back: RackHardwareClass = proto.try_into().unwrap();
            assert_eq!(back, model);
        }
    }

    #[test]
    fn test_rack_hardware_class_proto_unspecified_errors() {
        let result = RackHardwareClass::try_from(rpc::forge::RackHardwareClass::Unspecified);
        assert!(result.is_err());
    }

    #[test]
    fn test_rack_profile_proto_conversion() {
        let profile = RackProfile {
            rack_hardware_type: Some(RackHardwareType::from("dsx_gb200nvl_72x1")),
            rack_hardware_topology: Some(RackHardwareTopology::Gb200Nvl72r1C2g4Topology),
            rack_hardware_class: Some(RackHardwareClass::Prod),
            rack_capabilities: RackCapabilitiesSet {
                compute: RackCapabilityCompute {
                    name: Some("GB200".to_string()),
                    count: 18,
                    vendor: Some("NVIDIA".to_string()),
                    slot_ids: Some(vec![1, 2, 3]),
                },
                switch: RackCapabilitySwitch {
                    name: None,
                    count: 9,
                    vendor: None,
                    slot_ids: None,
                },
                power_shelf: RackCapabilityPowerShelf {
                    name: Some("PSU".to_string()),
                    count: 8,
                    vendor: Some("Delta".to_string()),
                    slot_ids: None,
                },
            },
        };

        let proto: rpc::forge::RackProfile = (&profile).into();

        assert_eq!(proto.rack_hardware_type.unwrap().value, "dsx_gb200nvl_72x1");
        assert_eq!(
            proto.rack_hardware_topology,
            rpc::forge::RackHardwareTopology::Gb200Nvl72r1C2g4 as i32
        );
        assert_eq!(
            proto.rack_hardware_class,
            rpc::forge::RackHardwareClass::Prod as i32
        );

        let caps = proto.capabilities.unwrap();
        let compute = caps.compute.unwrap();
        assert_eq!(compute.name, Some("GB200".to_string()));
        assert_eq!(compute.count, 18);
        assert_eq!(compute.vendor, Some("NVIDIA".to_string()));
        assert_eq!(compute.slot_ids, vec![1, 2, 3]);

        let switch = caps.switch.unwrap();
        assert_eq!(switch.name, None);
        assert_eq!(switch.count, 9);

        let power_shelf = caps.power_shelf.unwrap();
        assert_eq!(power_shelf.name, Some("PSU".to_string()));
        assert_eq!(power_shelf.count, 8);
        assert_eq!(power_shelf.vendor, Some("Delta".to_string()));
        assert_eq!(power_shelf.slot_ids, Vec::<u32>::new());
    }

    #[test]
    fn test_rack_profile_proto_conversion_with_defaults() {
        let profile = RackProfile::default();
        let proto: rpc::forge::RackProfile = (&profile).into();

        assert_eq!(proto.rack_hardware_type, None);
        assert_eq!(
            proto.rack_hardware_topology,
            rpc::forge::RackHardwareTopology::Unspecified as i32
        );
        assert_eq!(
            proto.rack_hardware_class,
            rpc::forge::RackHardwareClass::Unspecified as i32
        );
    }
}
