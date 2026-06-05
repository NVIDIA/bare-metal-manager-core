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

use model::firmware::FirmwareComponentType;

use crate::config::*;

#[test]
fn merging_config() -> eyre::Result<()> {
    let cfg1 = r#"
    vendor = "Dell"
    model = "PowerEdge R750"
    ordering = ["uefi", "bmc"]


    [components.uefi]
    current_version_reported_as = "^Installed-.*__BIOS.Setup."
    preingest_upgrade_when_below = "1.13.2"

    [[components.uefi.known_firmware]]
    version = "1.13.2"
    url = "https://urm.nvidia.com/artifactory/sw-ngc-forge-cargo-local/misc/BIOS_T3H20_WN64_1.13.2.EXE"
    default = true
"#;
    let cfg2 = r#"
model = "PowerEdge R750"
vendor = "Dell"

[components.uefi]
current_version_reported_as = "^Installed-.*__BIOS.Setup."
preingest_upgrade_when_below = "1.13.3"

[[components.uefi.known_firmware]]
version = "1.13.3"
url = "https://urm.nvidia.com/artifactory/sw-ngc-forge-cargo-local/misc/BIOS_T3H20_WN64_1.13.2.EXE"
default = true

[components.bmc]
current_version_reported_as = "^Installed-.*__iDRAC."

[[components.bmc.known_firmware]]
version = "7.10.30.00"
filenames = ["/opt/carbide/iDRAC-with-Lifecycle-Controller_Firmware_HV310_WN64_7.10.30.00_A00.EXE", "/opt/carbide/iDRAC-with-Lifecycle-Controller_Firmware_HV310_WN64_7.10.30.00_A01.EXE"]
default = true
    "#;
    let mut config: FirmwareConfig = Default::default();
    config.add_test_override(cfg1.to_string());
    config.add_test_override(cfg2.to_string());

    println!("{config:#?}");
    let snapshot = config.create_snapshot();
    let server = snapshot.data.get("dell:poweredge r750").unwrap();
    assert_eq!(
        server
            .components
            .get(&FirmwareComponentType::Uefi)
            .unwrap()
            .known_firmware
            .len(),
        2
    );
    assert_eq!(
        server
            .components
            .get(&FirmwareComponentType::Bmc)
            .unwrap()
            .known_firmware
            .len(),
        1
    );
    assert_eq!(
        server
            .components
            .get(&FirmwareComponentType::Bmc)
            .unwrap()
            .known_firmware
            .first()
            .unwrap()
            .filenames
            .len(),
        2
    );
    assert_eq!(
        *server
            .components
            .get(&FirmwareComponentType::Uefi)
            .unwrap()
            .preingest_upgrade_when_below
            .as_ref()
            .unwrap(),
        "1.13.3".to_string()
    );
    Ok(())
}

#[test]
fn cx7_component_config_parses_as_first_class_component() -> eyre::Result<()> {
    let cfg = r#"
model = "DGXH100"
vendor = "Nvidia"
ordering = ["hgxbmc", "combinedbmcuefi", "uefi", "bmc", "cx7"]

[components.cx7]
current_version_reported_as = "^CX7_[0-9]+$"

[[components.cx7.known_firmware]]
version = "28.47.2682"
filename = "/opt/carbide/firmware/nvidia-dgxh100-cx7-28.47.2682/cx7.bin"
filenames = ["/opt/carbide/firmware/nvidia-dgxh100-cx7-28.47.2682/cx7.bin"]
default = true
power_drains_needed = 1

[[components.cx7.known_firmware.files]]
filename = "/opt/carbide/firmware/nvidia-dgxh100-cx7-28.47.2682/cx7.bin"
sha256 = "abc123"

[components.cx7.known_firmware.scout]
execution_timeout_seconds = 1800
artifact_download_timeout_seconds = 600

[components.cx7.known_firmware.scout.script]
filename = "/opt/carbide/firmware/nvidia-dgxh100-cx7-28.47.2682/scripts/cx7_upgrade.sh"
sha256 = "def456"
"#;
    let mut config: FirmwareConfig = Default::default();
    config.add_test_override(cfg.to_string());

    let snapshot = config.create_snapshot();
    let server = snapshot.data.get("nvidia:dgxh100").unwrap();
    assert_eq!(
        server.ordering.last().copied(),
        Some(FirmwareComponentType::Cx7)
    );

    let cx7 = server.components.get(&FirmwareComponentType::Cx7).unwrap();
    assert!(cx7.current_version_reported_as.is_some());
    let firmware = cx7.known_firmware.first().unwrap();
    assert_eq!(firmware.version, "28.47.2682");
    assert_eq!(firmware.power_drains_needed, Some(1));
    assert_eq!(firmware.files.len(), 1);

    let scout = firmware.scout.as_ref().unwrap();
    assert_eq!(scout.execution_timeout_seconds, 1800);
    assert_eq!(scout.artifact_download_timeout_seconds, 600);
    assert_eq!(
        scout.script.filename,
        "/opt/carbide/firmware/nvidia-dgxh100-cx7-28.47.2682/scripts/cx7_upgrade.sh"
    );
    Ok(())
}
