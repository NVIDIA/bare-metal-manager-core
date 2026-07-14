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

use model::machine_boot_interface::MachineBootInterface;

use crate as rpc;
use crate::errors::RpcDataConversionError;

impl From<MachineBootInterface> for rpc::forge::MachineBootInterface {
    fn from(boot_interface: MachineBootInterface) -> Self {
        rpc::forge::MachineBootInterface {
            mac_address: boot_interface.mac_address.to_string(),
            interface_id: Some(boot_interface.interface_id),
        }
    }
}

impl TryFrom<rpc::forge::MachineBootInterface> for MachineBootInterface {
    type Error = RpcDataConversionError;

    fn try_from(rpc: rpc::forge::MachineBootInterface) -> Result<Self, Self::Error> {
        let mac_address = rpc
            .mac_address
            .parse()
            .map_err(|e| RpcDataConversionError::InvalidArgument(format!("mac_address: {e}")))?;
        // `for_mac` owns the fully-populated rule -- both halves present and a
        // non-empty id -- so an incomplete wire pair never becomes a model pair.
        MachineBootInterface::for_mac(mac_address, rpc.interface_id)
            .ok_or(RpcDataConversionError::MissingArgument("interface_id"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_a_complete_pair() {
        let pair = MachineBootInterface {
            mac_address: "00:11:22:33:44:55".parse().unwrap(),
            interface_id: "NIC.Slot.7-1-1".to_string(),
        };

        let wire = rpc::forge::MachineBootInterface::from(pair.clone());
        assert_eq!(wire.mac_address, "00:11:22:33:44:55");
        assert_eq!(wire.interface_id.as_deref(), Some("NIC.Slot.7-1-1"));

        let back = MachineBootInterface::try_from(wire).expect("a complete pair converts back");
        assert_eq!(back, pair);
    }

    #[test]
    fn an_incomplete_wire_pair_is_refused() {
        // A MAC-only wire value is valid to *send* (the id may not be captured
        // yet) but never becomes the model type, which requires both halves.
        let wire = rpc::forge::MachineBootInterface {
            mac_address: "00:11:22:33:44:55".to_string(),
            interface_id: None,
        };
        assert!(matches!(
            MachineBootInterface::try_from(wire),
            Err(RpcDataConversionError::MissingArgument("interface_id"))
        ));

        let empty_id = rpc::forge::MachineBootInterface {
            mac_address: "00:11:22:33:44:55".to_string(),
            interface_id: Some(String::new()),
        };
        assert!(MachineBootInterface::try_from(empty_id).is_err());
    }

    #[test]
    fn an_unparseable_mac_is_refused() {
        let wire = rpc::forge::MachineBootInterface {
            mac_address: "not-a-mac".to_string(),
            interface_id: Some("NIC.Slot.7-1-1".to_string()),
        };
        assert!(matches!(
            MachineBootInterface::try_from(wire),
            Err(RpcDataConversionError::InvalidArgument(_))
        ));
    }
}
