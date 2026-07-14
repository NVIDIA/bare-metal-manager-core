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

use std::str::FromStr;

use carbide_uuid::machine::{MachineId, MachineInterfaceId};
use clap::Parser;
use mac_address::MacAddress;

#[derive(Parser, Debug)]
#[command(after_long_help = "\
EXAMPLES:

Set the boot interface by MAC address (must match exactly one managed interface):
    $ nico-admin-cli boot-interface set 12345678-1234-5678-90ab-cdef01234567 00:11:22:33:44:55

Set it by machine-interface UUID (exact, works even with duplicate MACs):
    $ nico-admin-cli boot-interface set 12345678-1234-5678-90ab-cdef01234567 \
    abcdef01-2345-6789-abcd-ef0123456789

Set and reboot the host so the new boot order takes effect immediately:
    $ nico-admin-cli boot-interface set 12345678-1234-5678-90ab-cdef01234567 \
    00:11:22:33:44:55 --reboot

Tip: 'boot-interface candidates <MACHINE_ID>' lists the candidate NICs with their MACs and UUIDs.
")]
pub struct Args {
    #[clap(help = "The machine whose boot interface to set")]
    pub machine: MachineId,
    #[clap(help = "The interface to boot from -- a machine-interface UUID or a MAC address")]
    pub interface: InterfaceSelector,
    #[clap(long, help = "Reboot the host after the update")]
    pub reboot: bool,
}

/// How the operator names the target interface: the `machine_interfaces` row
/// UUID (exact), or the NIC's MAC address (resolved against the machine's
/// managed rows, refused when ambiguous).
#[derive(Clone, Debug, PartialEq)]
pub enum InterfaceSelector {
    Id(MachineInterfaceId),
    Mac(MacAddress),
}

impl FromStr for InterfaceSelector {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if let Ok(id) = s.parse::<MachineInterfaceId>() {
            return Ok(Self::Id(id));
        }
        if let Ok(mac) = s.parse::<MacAddress>() {
            return Ok(Self::Mac(mac));
        }
        Err(format!(
            "`{s}` is neither a machine-interface UUID nor a MAC address"
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selector_parses_a_uuid_as_an_interface_id() {
        let parsed: InterfaceSelector = "abcdef01-2345-6789-abcd-ef0123456789".parse().unwrap();
        assert!(matches!(parsed, InterfaceSelector::Id(_)));
    }

    #[test]
    fn selector_parses_a_mac_address() {
        let parsed: InterfaceSelector = "00:11:22:33:44:55".parse().unwrap();
        assert_eq!(
            parsed,
            InterfaceSelector::Mac("00:11:22:33:44:55".parse().unwrap())
        );
    }

    #[test]
    fn selector_rejects_anything_else() {
        let err = "not-an-interface".parse::<InterfaceSelector>().unwrap_err();
        assert!(err.contains("neither a machine-interface UUID nor a MAC address"));
    }
}
