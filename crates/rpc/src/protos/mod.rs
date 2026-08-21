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

// Each module's body is loaded from OUT_DIR, where build.rs writes the generated code.
// Using `include!` with concat/env lets us keep generated files out of the source tree
// entirely.

#[allow(non_snake_case, unknown_lints, clippy::all)]
#[rustfmt::skip]
pub mod common {
    include!(concat!(env!("OUT_DIR"), "/common.rs"));
}

#[allow(non_snake_case, unknown_lints, clippy::all)]
#[rustfmt::skip]
pub mod scout_firmware_upgrade {
    include!(concat!(env!("OUT_DIR"), "/scout_firmware_upgrade.rs"));
}

#[allow(non_snake_case, unknown_lints, clippy::all)]
#[rustfmt::skip]
pub mod forge {
    include!(concat!(env!("OUT_DIR"), "/forge.rs"));

    /// Expected-interface Rust name for the legacy protobuf
    /// `ExpectedHostNic` boundary.
    ///
    /// The protobuf descriptor keeps its existing message and field names so
    /// deployed clients remain protobuf wire- and ProtoJSON-compatible. New
    /// Rust callers should use this alias and the accessors below.
    pub type ExpectedInterface = ExpectedHostNic;

    impl ExpectedMachine {
        /// Return the interfaces from the legacy `host_nics` protobuf field.
        pub fn interfaces(&self) -> &[ExpectedInterface] {
            &self.host_nics
        }

        /// Return mutable interfaces from the legacy `host_nics` protobuf
        /// field.
        pub fn interfaces_mut(&mut self) -> &mut Vec<ExpectedInterface> {
            &mut self.host_nics
        }
    }
}

#[allow(non_snake_case, unknown_lints, clippy::all)]
#[rustfmt::skip]
pub mod health {
    include!(concat!(env!("OUT_DIR"), "/health.rs"));
}

#[allow(non_snake_case, unknown_lints, clippy::all)]
#[rustfmt::skip]
pub mod machine_discovery {
    include!(concat!(env!("OUT_DIR"), "/machine_discovery.rs"));
}

impl machine_discovery::MemoryDeviceGroup {
    /// Mirrors `carbide_api_model::hardware_info::MAX_MEMORY_DEVICE_COUNT`
    /// (`crates/api-model/src/hardware_info.rs`). Duplicated here (rather than depended on)
    /// because `carbide-api-model` is only an optional dependency of this crate, gated behind
    /// the `model` feature, while this proto helper is unconditional. Update both if this value
    /// changes.
    ///
    /// Bounds [`Self::rehydrate`] so it can't allocate an unbounded `Vec` even if a caller
    /// invokes it on a group that bypassed the checked conversions in `rpc::model::hardware_info`
    /// or `carbide-api-model` (which already reject any `count` above this limit).
    const MAX_REHYDRATE_COUNT: u32 = 8192;

    /// Returns `Some(self)` when `count > 0`, `None` otherwise.
    ///
    /// Use at ingestion boundaries to drop proto groups that carry no devices.
    pub fn nonzero(self) -> Option<Self> {
        (self.count > 0).then_some(self)
    }

    /// Expands this group back into a flat iterator of individual [`machine_discovery::MemoryDevice`]s.
    ///
    /// `count` is capped at [`Self::MAX_REHYDRATE_COUNT`] so a corrupted or otherwise unvalidated
    /// group can't force an unbounded allocation.
    pub fn rehydrate(&self) -> impl Iterator<Item = machine_discovery::MemoryDevice> + '_ {
        std::iter::repeat_n(
            machine_discovery::MemoryDevice {
                size_mb: self.size_mb,
                mem_type: self.mem_type.clone(),
            },
            self.count.min(Self::MAX_REHYDRATE_COUNT) as usize,
        )
    }
}

impl machine_discovery::DiscoveryInfo {
    /// Rehydrates the deprecated flat `memory_devices` list from `memory_device_groups` and
    /// clears the groups, so a raw dump of this `DiscoveryInfo` stays byte-for-byte identical
    /// to the pre-condensing output, which only ever had `memory_devices`.
    ///
    /// Group order (and thus device order) is preserved: groups only merge consecutive
    /// identical devices, and `rehydrate()` expands each group to `count` copies in place.
    #[allow(deprecated)]
    pub fn rehydrate_memory_devices(&mut self) {
        if self.memory_devices.is_empty() && !self.memory_device_groups.is_empty() {
            self.memory_devices = self
                .memory_device_groups
                .iter()
                .flat_map(|group| group.rehydrate())
                .collect();
        }
        self.memory_device_groups.clear();
    }
}

#[allow(non_snake_case, unknown_lints, clippy::all)]
#[rustfmt::skip]
pub mod measured_boot {
    include!(concat!(env!("OUT_DIR"), "/measured_boot.rs"));
}

#[allow(non_snake_case, unknown_lints, clippy::all)]
#[rustfmt::skip]
pub mod mlx_device {
    include!(concat!(env!("OUT_DIR"), "/mlx_device.rs"));
}

#[allow(non_snake_case, unknown_lints, clippy::all)]
#[rustfmt::skip]
pub mod site_explorer {
    include!(concat!(env!("OUT_DIR"), "/site_explorer.rs"));

    /// Observed-state Rust name for the legacy protobuf `NicMode` boundary.
    ///
    /// The protobuf descriptor retains `NicMode` for compatibility with
    /// existing generated clients. New Rust callers should use this alias.
    pub type BlueFieldOperatingMode = NicMode;
}

#[allow(non_snake_case, unknown_lints, clippy::all)]
#[rustfmt::skip]
pub mod dns {
    include!(concat!(env!("OUT_DIR"), "/dns.rs"));
}

#[allow(non_snake_case, unknown_lints, clippy::all)]
#[rustfmt::skip]
pub mod fmds {
    include!(concat!(env!("OUT_DIR"), "/fmds.rs"));
}

#[allow(non_snake_case, unknown_lints, clippy::all)]
#[rustfmt::skip]
pub mod agent_local {
    include!(concat!(env!("OUT_DIR"), "/agent_local.rs"));
}

#[allow(clippy::all, deprecated)]
#[rustfmt::skip]
pub mod forge_api_client {
    include!(concat!(env!("OUT_DIR"), "/forge_api_client.rs"));
}

#[allow(clippy::all)]
#[rustfmt::skip]
pub mod convenience_converters {
    include!(concat!(env!("OUT_DIR"), "/convenience_converters.rs"));
}

#[allow(clippy::all)]
#[rustfmt::skip]
pub mod nmx_c {
    include!(concat!(env!("OUT_DIR"), "/nmx_c.rs"));
}

#[allow(clippy::all)]
#[rustfmt::skip]
pub mod nmx_c_client {
    include!(concat!(env!("OUT_DIR"), "/nmx_c_client.rs"));
}

#[allow(clippy::all)]
#[rustfmt::skip]
pub mod nmx_c_converters {
    include!(concat!(env!("OUT_DIR"), "/nmx_c_converters.rs"));
}
