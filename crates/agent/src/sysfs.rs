/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */
use std::ffi::OsString;
use std::fs::{self, DirEntry, File};
use std::io::{Read, Result};

const SYSFS_NET_BASE: &str = "/sys/class/net";

pub fn get_net_devices() -> Result<Vec<SysfsNetDevice>> {
    let net_device_entries = fs::read_dir(SYSFS_NET_BASE)?;
    net_device_entries
        .map(|entry| entry.map(SysfsNetDevice::from))
        .collect()
}

pub struct SysfsNetDevice {
    dir_entry: DirEntry,
}

impl SysfsNetDevice {
    pub fn is_pci_device(&self) -> Result<bool> {
        const PCI_PREFIX: &str = "../../devices/pci";
        let link_target = fs::read_link(self.dir_entry.path());
        link_target.map(|link_target| {
            link_target
                .as_os_str()
                .as_encoded_bytes()
                .starts_with(PCI_PREFIX.as_bytes())
        })
    }

    // Return the contents of /sys/class/net/${device}/address -- this is
    // not guaranteed to be in any particular format but we optimize for a
    // human-readable EUI-48 (colon-separated hex bytes). No whitespace is
    // removed, so there will probably be a newline at the end.
    pub fn _get_encoded_address(&self) -> Result<Vec<u8>> {
        const ASCII_EUI48_WITH_NEWLINE_LENGTH: usize = 18;
        let mut address_contents = Vec::with_capacity(ASCII_EUI48_WITH_NEWLINE_LENGTH);
        let address_path = {
            let mut device_path = self.dir_entry.path();
            device_path.push("address");
            device_path
        };
        File::open(address_path)
            .and_then(|mut address_file| address_file.read_to_end(&mut address_contents))
            .and(Ok(address_contents))
    }

    pub fn entry_name(&self) -> OsString {
        self.dir_entry.file_name()
    }
}

impl From<DirEntry> for SysfsNetDevice {
    fn from(dir_entry: DirEntry) -> Self {
        SysfsNetDevice { dir_entry }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[cfg(target_os = "linux")]
    #[test]
    fn test_sysfs_net_devices() {
        let net_devices = get_net_devices().expect("Couldn't get sysfs network devices");
        assert!(!net_devices.is_empty());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_lo_is_not_pci_device() {
        let net_devices = get_net_devices().expect("Couldn't get sysfs network devices");
        let lo_device = net_devices
            .iter()
            .find(|d| d.entry_name().as_encoded_bytes() == "lo".as_bytes())
            .expect("Couldn't find lo network device");
        let lo_is_pci_device = lo_device.is_pci_device().unwrap();
        assert!(!lo_is_pci_device);
    }
}
