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

use carbide_network::virtualization::VpcVirtualizationType;

use crate::{RpcDataConversionError, forge as rpc};

impl From<rpc::VpcVirtualizationType> for VpcVirtualizationType {
    fn from(v: rpc::VpcVirtualizationType) -> Self {
        match v {
            rpc::VpcVirtualizationType::EthernetVirtualizer => Self::EthernetVirtualizer,
            // ETHERNET_VIRTUALIZER_WITH_NVUE is equivalent to EthernetVirtualizer
            #[allow(deprecated)]
            rpc::VpcVirtualizationType::EthernetVirtualizerWithNvue => Self::EthernetVirtualizer,
            rpc::VpcVirtualizationType::Fnn => Self::Fnn,
            rpc::VpcVirtualizationType::Flat => Self::Flat,
            // Following are deprecated.
            rpc::VpcVirtualizationType::FnnClassic => Self::Fnn,
            rpc::VpcVirtualizationType::FnnL3 => Self::Fnn,
        }
    }
}

impl From<VpcVirtualizationType> for rpc::VpcVirtualizationType {
    fn from(nvt: VpcVirtualizationType) -> Self {
        match nvt {
            VpcVirtualizationType::EthernetVirtualizer
            | VpcVirtualizationType::EthernetVirtualizerWithNvue => {
                rpc::VpcVirtualizationType::EthernetVirtualizer
            }
            VpcVirtualizationType::Fnn => rpc::VpcVirtualizationType::Fnn,
            VpcVirtualizationType::Flat => rpc::VpcVirtualizationType::Flat,
        }
    }
}

pub fn vpc_virtualization_type_try_from_rpc(
    value: i32,
) -> Result<VpcVirtualizationType, RpcDataConversionError> {
    Ok(match value {
        x if x == rpc::VpcVirtualizationType::EthernetVirtualizer as i32 => {
            VpcVirtualizationType::EthernetVirtualizer
        }
        // If we get proto enum field 2, which is ETHERNET_VIRTUALIZER_WITH_NVUE,
        // just map it to EthernetVirtualizer.
        #[allow(deprecated)]
        x if x == rpc::VpcVirtualizationType::EthernetVirtualizerWithNvue as i32 => {
            VpcVirtualizationType::EthernetVirtualizer
        }
        x if x == rpc::VpcVirtualizationType::Fnn as i32 => VpcVirtualizationType::Fnn,
        x if x == rpc::VpcVirtualizationType::Flat as i32 => VpcVirtualizationType::Flat,
        _ => {
            return Err(RpcDataConversionError::InvalidVpcVirtualizationType(value));
        }
    })
}

#[cfg(test)]
mod test {
    use carbide_network::virtualization::VpcVirtualizationType;

    use super::*;

    #[test]
    fn from_rpc_etv_with_nvue_maps_to_etv() {
        #[allow(deprecated)]
        let vtype: VpcVirtualizationType =
            rpc::VpcVirtualizationType::EthernetVirtualizerWithNvue.into();
        assert_eq!(vtype, VpcVirtualizationType::EthernetVirtualizer);
    }

    #[test]
    fn to_rpc_etv_maps_to_proto_etv() {
        let rpc_vtype: rpc::VpcVirtualizationType =
            VpcVirtualizationType::EthernetVirtualizer.into();
        assert_eq!(rpc_vtype, rpc::VpcVirtualizationType::EthernetVirtualizer);
    }

    #[test]
    fn proto_value_2_maps_to_etv() {
        // Make sure our proto From implementation turns
        // ETHERNET_VIRTUALIZER_WITH_NVUE into EthernetVirtualizer.
        let vtype = vpc_virtualization_type_try_from_rpc(2).unwrap();
        assert_eq!(vtype, VpcVirtualizationType::EthernetVirtualizer);
    }

    #[test]
    fn proto_value_0_maps_to_etv() {
        let vtype = vpc_virtualization_type_try_from_rpc(0).unwrap();
        assert_eq!(vtype, VpcVirtualizationType::EthernetVirtualizer);
    }

    #[test]
    fn flat_round_trips() {
        let rpc_vtype: rpc::VpcVirtualizationType = VpcVirtualizationType::Flat.into();
        assert_eq!(rpc_vtype, rpc::VpcVirtualizationType::Flat);

        let vtype: VpcVirtualizationType = rpc::VpcVirtualizationType::Flat.into();
        assert_eq!(vtype, VpcVirtualizationType::Flat);

        let vtype =
            vpc_virtualization_type_try_from_rpc(rpc::VpcVirtualizationType::Flat as i32).unwrap();
        assert_eq!(vtype, VpcVirtualizationType::Flat);
    }
}
