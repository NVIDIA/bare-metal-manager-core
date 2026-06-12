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
    use carbide_test_support::Outcome::*;
    use carbide_test_support::{Case, Check, check_cases, check_values};

    use super::*;

    // proto -> model: `From<rpc::VpcVirtualizationType>` (infallible).
    #[test]
    fn from_rpc_maps_to_model() {
        #[allow(deprecated)]
        check_values(
            [
                Check {
                    scenario: "etv-with-nvue maps to etv",
                    input: rpc::VpcVirtualizationType::EthernetVirtualizerWithNvue,
                    expect: VpcVirtualizationType::EthernetVirtualizer,
                },
                Check {
                    scenario: "flat round-trips to flat",
                    input: rpc::VpcVirtualizationType::Flat,
                    expect: VpcVirtualizationType::Flat,
                },
            ],
            |v| v.into(),
        );
    }

    // model -> proto: `From<VpcVirtualizationType>` (infallible).
    #[test]
    fn to_rpc_maps_to_proto() {
        check_values(
            [
                Check {
                    scenario: "etv maps to proto etv",
                    input: VpcVirtualizationType::EthernetVirtualizer,
                    expect: rpc::VpcVirtualizationType::EthernetVirtualizer,
                },
                Check {
                    scenario: "flat round-trips to proto flat",
                    input: VpcVirtualizationType::Flat,
                    expect: rpc::VpcVirtualizationType::Flat,
                },
            ],
            |v| v.into(),
        );
    }

    // proto i32 -> model: `vpc_virtualization_type_try_from_rpc` (fallible).
    #[test]
    fn try_from_rpc_i32_maps_to_model() {
        check_cases(
            [
                Case {
                    // proto field 2, ETHERNET_VIRTUALIZER_WITH_NVUE, maps to etv.
                    scenario: "value 2 maps to etv",
                    input: 2,
                    expect: Yields(VpcVirtualizationType::EthernetVirtualizer),
                },
                Case {
                    scenario: "value 0 maps to etv",
                    input: 0,
                    expect: Yields(VpcVirtualizationType::EthernetVirtualizer),
                },
                Case {
                    scenario: "flat round-trips from i32",
                    input: rpc::VpcVirtualizationType::Flat as i32,
                    expect: Yields(VpcVirtualizationType::Flat),
                },
            ],
            |value| vpc_virtualization_type_try_from_rpc(value).map_err(drop),
        );
    }
}
