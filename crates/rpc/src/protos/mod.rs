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
