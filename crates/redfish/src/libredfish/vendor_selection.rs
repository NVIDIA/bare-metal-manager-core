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

use libredfish::model::service_root::RedfishVendor;

/// How `create_client` picks the vendor implementation a client dispatches on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VendorSelection {
    /// Detect the vendor from the BMC service root.
    /// An operator pin wins instead, since a pin exists for wrong detection.
    Detect,
    /// A vendor the caller resolved itself, from DMI or a probe.
    /// An operator pin outranks it, being the operator correction to detection.
    Hint(RedfishVendor),
    /// Probe and bootstrap mode, an uninitialized client that fetches nothing.
    /// Never pinned, as factory GBx00 BMCs refuse `/Systems` until rotation.
    Uninitialized,
}

/// The client construction mode after any operator pin has been applied.
/// Separate from [`VendorSelection`] so precedence stays one pure function.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ClientMode {
    Detect,
    Vendor(RedfishVendor),
    Uninitialized,
}

impl VendorSelection {
    /// Apply the operator pin to this selection.
    /// A pin wins over `Detect` and `Hint`, and `Uninitialized` ignores it.
    pub(crate) fn resolve(self, pin: Option<RedfishVendor>) -> ClientMode {
        match (self, pin) {
            // Never pinnable. The caller asked for a client that can reach a BMC
            // no vendor client can initialize against yet.
            (Self::Uninitialized, _) => ClientMode::Uninitialized,
            (Self::Detect | Self::Hint(_), Some(pinned)) => ClientMode::Vendor(pinned),
            (Self::Detect, None) => ClientMode::Detect,
            (Self::Hint(vendor), None) => ClientMode::Vendor(vendor),
        }
    }
}

#[cfg(test)]
mod tests {
    use carbide_test_support::value_scenarios;

    use super::*;

    #[test]
    fn pin_outranks_detection_but_never_the_uninitialized_mode() {
        value_scenarios!(
            run = |(selection, pin): (VendorSelection, Option<RedfishVendor>)| selection
                .resolve(pin);

            "no pin leaves the caller's intent intact" {
                (VendorSelection::Detect, None) => ClientMode::Detect,
                (VendorSelection::Hint(RedfishVendor::Dell), None)
                    => ClientMode::Vendor(RedfishVendor::Dell),
                (VendorSelection::Uninitialized, None) => ClientMode::Uninitialized,
            }

            "a pin wins over detection and over a caller-resolved vendor" {
                (VendorSelection::Detect, Some(RedfishVendor::Dell))
                    => ClientMode::Vendor(RedfishVendor::Dell),
                (VendorSelection::Hint(RedfishVendor::NvidiaGBx00), Some(RedfishVendor::Dell))
                    => ClientMode::Vendor(RedfishVendor::Dell),
            }

            // The rule factory BMC bootstrap and credential rotation depend on.
            // If this row ever flips, rotation deadlocks on factory GBx00 BMCs.
            "a pin never reaches the uninitialized mode" {
                (VendorSelection::Uninitialized, Some(RedfishVendor::Dell))
                    => ClientMode::Uninitialized,
            }
        );
    }
}
