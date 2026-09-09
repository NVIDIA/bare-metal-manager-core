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

use std::collections::BTreeMap;
use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Output};
use std::sync::{Arc, Mutex, OnceLock, Weak};

use quick_xml::events::{BytesEnd, BytesStart, Event};
use quick_xml::{Reader, Writer};
use url::Url;

use crate::redfish::computer_system::{SingleSystemState, SystemState};
use crate::{BmcState, Callbacks, MockPowerState, SetSystemPowerError, SystemPowerControl};

#[derive(Debug, thiserror::Error)]
enum VirtualMediaError {
    #[error("invalid virtual media request: {0}")]
    BadRequest(String),
    #[error("virtual media command failed: {0}")]
    Command(String),
}

type VirtualMediaResult = Result<(), VirtualMediaError>;

#[derive(Clone, Debug)]
pub struct Config {
    pub virsh_path: PathBuf,
    pub uri: String,
    pub domain: String,
    pub virtual_media_targets: BTreeMap<String, String>,
}

#[derive(Debug)]
pub struct LibvirtCallbacks {
    config: Config,
    restore_boot_after_power_on: Mutex<bool>,
    system_state: OnceLock<Weak<SystemState>>,
    applied_state: Mutex<AppliedState>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
struct AppliedState {
    boot_source_override: serde_json::Value,
    virtual_media: BTreeMap<String, serde_json::Value>,
}

impl LibvirtCallbacks {
    pub fn new(config: Config) -> Self {
        Self {
            config,
            restore_boot_after_power_on: Mutex::new(false),
            system_state: OnceLock::new(),
            applied_state: Mutex::new(AppliedState::default()),
        }
    }

    pub fn bind_state(&self, state: &BmcState) -> Result<(), String> {
        let controlled_system = state
            .system_state
            .controlled_system()
            .ok_or_else(|| "libvirt backend has no controlled ComputerSystem".to_string())?;
        self.system_state
            .set(Arc::downgrade(&state.system_state))
            .map_err(|_| "libvirt backend state is already bound".to_string())?;

        let desired = AppliedState::from(controlled_system);
        for device_id in desired.virtual_media.keys() {
            self.ensure_virtual_media_device(device_id)
                .map_err(|error| error.to_string())?;
        }
        *self.applied_state.lock().unwrap() = AppliedState::default();
        self.reconcile_state(desired)
    }

    fn virsh_output(&self, arguments: &[&str]) -> Result<Output, String> {
        Command::new(&self.config.virsh_path)
            .arg("--connect")
            .arg(&self.config.uri)
            .args(arguments)
            .output()
            .map_err(|error| {
                format!(
                    "could not execute {}: {error}",
                    self.config.virsh_path.display()
                )
            })
    }

    fn virsh(&self, arguments: &[&str]) -> Result<Output, String> {
        let output = self.virsh_output(arguments)?;
        if output.status.success() {
            return Ok(output);
        }
        Err(format!(
            "{} exited with {}: {}",
            self.config.virsh_path.display(),
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        ))
    }

    fn domain_command(&self, command: &str) -> Result<(), SetSystemPowerError> {
        self.virsh(&[command, &self.config.domain])
            .map(drop)
            .map_err(SetSystemPowerError::CommandSendError)
    }

    fn start(&self) -> Result<(), SetSystemPowerError> {
        self.domain_command("start")?;
        let restore_boot = {
            let mut restore_boot_after_power_on = self.restore_boot_after_power_on.lock().unwrap();
            std::mem::take(&mut *restore_boot_after_power_on)
        };
        if restore_boot {
            self.set_boot_devices(&["hd"])?;
        }
        Ok(())
    }

    fn set_boot_devices(&self, devices: &[&str]) -> Result<(), SetSystemPowerError> {
        let output = self
            .virsh(&["dumpxml", "--inactive", &self.config.domain])
            .map_err(SetSystemPowerError::CommandSendError)?;
        let xml = String::from_utf8(output.stdout).map_err(|error| {
            SetSystemPowerError::CommandSendError(format!(
                "virsh dumpxml returned invalid UTF-8: {error}"
            ))
        })?;
        let xml =
            set_boot_order_xml(&xml, devices).map_err(SetSystemPowerError::CommandSendError)?;
        let mut file = tempfile::NamedTempFile::new().map_err(|error| {
            SetSystemPowerError::CommandSendError(format!(
                "could not create temporary domain XML: {error}"
            ))
        })?;
        file.write_all(xml.as_bytes()).map_err(|error| {
            SetSystemPowerError::CommandSendError(format!(
                "could not write temporary domain XML: {error}"
            ))
        })?;
        self.virsh(&["define", file.path().to_string_lossy().as_ref()])
            .map(drop)
            .map_err(SetSystemPowerError::CommandSendError)
    }

    fn target_for_device(&self, device_id: &str) -> Result<&str, VirtualMediaError> {
        self.config
            .virtual_media_targets
            .get(device_id)
            .map(String::as_str)
            .ok_or_else(|| {
                VirtualMediaError::BadRequest(format!(
                    "virtual media device {device_id} has no libvirt target"
                ))
            })
    }

    fn domain_xml(&self, inactive: bool) -> Result<String, VirtualMediaError> {
        let arguments = if inactive {
            vec!["dumpxml", "--inactive", self.config.domain.as_str()]
        } else {
            vec!["dumpxml", self.config.domain.as_str()]
        };
        let output = self.virsh(&arguments).map_err(VirtualMediaError::Command)?;
        String::from_utf8(output.stdout).map_err(|error| {
            VirtualMediaError::Command(format!("virsh dumpxml returned invalid UTF-8: {error}"))
        })
    }

    fn require_owned_target(
        &self,
        device_id: &str,
        target: &str,
        inactive: bool,
    ) -> VirtualMediaResult {
        let xml = self.domain_xml(inactive)?;
        match virtual_media_target_ownership(&xml, device_id, target)
            .map_err(VirtualMediaError::Command)?
        {
            TargetOwnership::Owned => Ok(()),
            TargetOwnership::Missing => Err(VirtualMediaError::Command(format!(
                "libvirt domain {} has no {} virtual-media CD-ROM at target {target}",
                self.config.domain,
                if inactive { "persistent" } else { "live" },
            ))),
            TargetOwnership::Foreign { device, bus, alias } => {
                Err(VirtualMediaError::Command(format!(
                    "libvirt target {target} is already used by an unowned device (device={}, bus={}, alias={})",
                    device.as_deref().unwrap_or("unknown"),
                    bus.as_deref().unwrap_or("unknown"),
                    alias.as_deref().unwrap_or("none"),
                )))
            }
        }
    }

    fn ensure_virtual_media_device(&self, device_id: &str) -> VirtualMediaResult {
        let target = self.target_for_device(device_id)?;
        let xml = self.domain_xml(true)?;
        match virtual_media_target_ownership(&xml, device_id, target)
            .map_err(VirtualMediaError::Command)?
        {
            TargetOwnership::Owned => return Ok(()),
            TargetOwnership::Foreign { device, bus, alias } => {
                return Err(VirtualMediaError::Command(format!(
                    "refusing to claim libvirt target {target}: it is already used by an unowned device (device={}, bus={}, alias={})",
                    device.as_deref().unwrap_or("unknown"),
                    bus.as_deref().unwrap_or("unknown"),
                    alias.as_deref().unwrap_or("none"),
                )));
            }
            TargetOwnership::Missing => {}
        }

        let xml = empty_virtual_media_xml(device_id, target)?;
        let mut file = tempfile::NamedTempFile::new().map_err(|error| {
            VirtualMediaError::Command(format!("could not create temporary device XML: {error}"))
        })?;
        file.write_all(xml.as_bytes()).map_err(|error| {
            VirtualMediaError::Command(format!("could not write temporary device XML: {error}"))
        })?;
        self.virsh(&[
            "attach-device",
            &self.config.domain,
            file.path().to_string_lossy().as_ref(),
            "--config",
        ])
        .map(drop)
        .map_err(VirtualMediaError::Command)
    }

    fn domain_is_active(&self) -> Result<bool, VirtualMediaError> {
        let output = self
            .virsh(&["domstate", &self.config.domain])
            .map_err(VirtualMediaError::Command)?;
        let state = String::from_utf8(output.stdout).map_err(|error| {
            VirtualMediaError::Command(format!("virsh domstate returned invalid UTF-8: {error}"))
        })?;
        match state.trim() {
            "running" | "idle" | "blocked" | "paused" | "in shutdown" | "pmsuspended" => Ok(true),
            "shut off" | "crashed" => Ok(false),
            state => Err(VirtualMediaError::Command(format!(
                "virsh domstate returned an unknown domain state: {state}"
            ))),
        }
    }

    fn set_boot_source_override(
        &self,
        boot_source_override: &serde_json::Value,
    ) -> Result<(), SetSystemPowerError> {
        let enabled = boot_source_override
            .get("BootSourceOverrideEnabled")
            .and_then(serde_json::Value::as_str);
        let target = boot_source_override
            .get("BootSourceOverrideTarget")
            .and_then(serde_json::Value::as_str);
        let devices = match (enabled, target) {
            (Some("Disabled"), _) | (_, Some("None")) => &["hd"][..],
            (_, Some("Cd")) => &["cdrom", "hd"][..],
            (_, Some("Hdd")) => &["hd"][..],
            (_, Some("Pxe" | "UefiHttp")) => &["network", "hd"][..],
            (_, Some(target)) => {
                return Err(SetSystemPowerError::BadRequest(format!(
                    "unsupported boot source override target: {target}"
                )));
            }
            (_, None) => return Ok(()),
        };
        self.set_boot_devices(devices)?;
        *self.restore_boot_after_power_on.lock().unwrap() =
            enabled == Some("Once") && target != Some("Hdd");
        Ok(())
    }

    fn insert_virtual_media(
        &self,
        device_id: &str,
        image: &str,
        write_protected: bool,
    ) -> VirtualMediaResult {
        let target = self.target_for_device(device_id)?;
        let xml = virtual_media_xml(device_id, target, image, write_protected)?;
        self.update_virtual_media(device_id, target, &xml)
    }

    fn update_virtual_media(&self, device_id: &str, target: &str, xml: &str) -> VirtualMediaResult {
        self.require_owned_target(device_id, target, true)?;
        let active = self.domain_is_active()?;
        if active {
            self.require_owned_target(device_id, target, false)?;
        }

        let mut file = tempfile::NamedTempFile::new().map_err(|error| {
            VirtualMediaError::Command(format!("could not create temporary device XML: {error}"))
        })?;
        file.write_all(xml.as_bytes()).map_err(|error| {
            VirtualMediaError::Command(format!("could not write temporary device XML: {error}"))
        })?;
        let file_path = file.path().to_string_lossy();
        let mut arguments = vec![
            "update-device",
            self.config.domain.as_str(),
            file_path.as_ref(),
        ];
        if active {
            arguments.push("--live");
        }
        arguments.push("--config");
        self.virsh(&arguments)
            .map(drop)
            .map_err(VirtualMediaError::Command)
    }

    fn eject_virtual_media(&self, device_id: &str) -> VirtualMediaResult {
        let target = self.target_for_device(device_id)?;
        let xml = empty_virtual_media_xml(device_id, target)?;
        self.update_virtual_media(device_id, target, &xml)
    }

    fn apply_virtual_media(&self, state: &serde_json::Value) -> VirtualMediaResult {
        let device_id = state
            .get("Id")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| {
                VirtualMediaError::BadRequest("virtual media state has no Id".to_string())
            })?;
        let inserted = state
            .get("Inserted")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false);
        if !inserted {
            return self.eject_virtual_media(device_id);
        }
        let image = state
            .get("Image")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| {
                VirtualMediaError::BadRequest(format!(
                    "inserted virtual media device {device_id} has no Image"
                ))
            })?;
        let write_protected = state
            .get("WriteProtected")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(true);
        self.insert_virtual_media(device_id, image, write_protected)
    }

    fn reconcile_state(&self, desired: AppliedState) -> Result<(), String> {
        let mut applied = self.applied_state.lock().unwrap();
        if desired.boot_source_override != applied.boot_source_override {
            self.set_boot_source_override(&desired.boot_source_override)
                .map_err(|error| error.to_string())?;
            applied.boot_source_override = desired.boot_source_override;
        }
        for (device_id, desired_device) in desired.virtual_media {
            if applied.virtual_media.get(&device_id) == Some(&desired_device) {
                continue;
            }
            if let Err(error) = self.apply_virtual_media(&desired_device) {
                // The command may have failed after changing one libvirt view. Forget the
                // cached value so a caller restoring its previous Redfish state forces a
                // compensating update instead of treating the old state as already applied.
                applied.virtual_media.remove(&device_id);
                return Err(error.to_string());
            }
            applied.virtual_media.insert(device_id, desired_device);
        }
        Ok(())
    }
}

impl From<&SingleSystemState> for AppliedState {
    fn from(system: &SingleSystemState) -> Self {
        let virtual_media = system
            .virtual_media()
            .into_iter()
            .flat_map(|virtual_media| virtual_media.desired_state())
            .filter_map(|state| {
                let device_id = state
                    .get("Id")
                    .and_then(serde_json::Value::as_str)?
                    .to_string();
                Some((device_id, state))
            })
            .collect();
        Self {
            boot_source_override: system.boot_source_override(),
            virtual_media,
        }
    }
}

impl Callbacks for LibvirtCallbacks {
    fn get_power_state(&self) -> MockPowerState {
        match self.virsh(&["domstate", &self.config.domain]) {
            Ok(output) => match String::from_utf8_lossy(&output.stdout).trim() {
                "running" | "idle" | "blocked" | "paused" | "in shutdown" | "pmsuspended" => {
                    MockPowerState::On
                }
                _ => MockPowerState::Off,
            },
            Err(error) => {
                tracing::warn!(
                    domain = %self.config.domain,
                    error,
                    "could not read libvirt domain power state",
                );
                MockPowerState::Off
            }
        }
    }

    fn send_power_command(
        &self,
        reset_type: SystemPowerControl,
    ) -> Result<(), SetSystemPowerError> {
        use SystemPowerControl::*;
        match reset_type {
            On | ForceOn => self.start(),
            GracefulShutdown => self.domain_command("shutdown"),
            ForceOff => self.domain_command("destroy"),
            GracefulRestart => self.domain_command("reboot"),
            ForceRestart => self.domain_command("reset"),
            PowerCycle => {
                self.domain_command("destroy")?;
                self.start()
            }
            Pause => self.domain_command("suspend"),
            Resume => self.domain_command("resume"),
            Nmi => self.domain_command("inject-nmi"),
            PushPowerButton | Suspend => Err(SetSystemPowerError::BadRequest(format!(
                "libvirt backend does not support {reset_type:?}"
            ))),
        }
    }

    fn state_refresh_indication(&self) -> Result<(), String> {
        let Some(system_state) = self.system_state.get().and_then(Weak::upgrade) else {
            return Err("libvirt backend is not bound to BMC mock state".to_string());
        };
        let Some(controlled_system) = system_state.controlled_system() else {
            return Err("BMC mock state has no controlled ComputerSystem".to_string());
        };
        self.reconcile_state(AppliedState::from(controlled_system))
    }
}

fn set_boot_order_xml(xml: &str, devices: &[&str]) -> Result<String, String> {
    let mut reader = Reader::from_str(xml);
    reader.config_mut().trim_text(false);
    let mut writer = Writer::new(Vec::new());
    let mut inside_os = false;
    loop {
        let event = reader
            .read_event()
            .map_err(|error| format!("could not parse libvirt domain XML: {error}"))?;
        match event {
            Event::Start(start) if start.name().as_ref() == b"os" => {
                inside_os = true;
                writer.write_event(Event::Start(start.into_owned()))
            }
            Event::Empty(empty) if inside_os && empty.name().as_ref() == b"boot" => Ok(()),
            Event::End(end) if end.name().as_ref() == b"os" => {
                let result: std::io::Result<()> = (|| {
                    for device in devices {
                        let mut boot = BytesStart::new("boot");
                        boot.push_attribute(("dev", *device));
                        writer.write_event(Event::Empty(boot))?;
                    }
                    inside_os = false;
                    writer.write_event(Event::End(BytesEnd::new("os")))
                })();
                result
            }
            Event::Eof => break,
            event => writer.write_event(event.into_owned()),
        }
        .map_err(|error| format!("could not write libvirt domain XML: {error}"))?;
    }
    String::from_utf8(writer.into_inner())
        .map_err(|error| format!("generated libvirt domain XML is invalid UTF-8: {error}"))
}

#[derive(Debug, Eq, PartialEq)]
enum TargetOwnership {
    Missing,
    Owned,
    Foreign {
        device: Option<String>,
        bus: Option<String>,
        alias: Option<String>,
    },
}

fn xml_attribute(element: &BytesStart<'_>, name: &[u8]) -> Result<Option<String>, String> {
    for attribute in element.attributes() {
        let attribute = attribute
            .map_err(|error| format!("could not parse libvirt domain XML attribute: {error}"))?;
        if attribute.key.as_ref() == name {
            return String::from_utf8(attribute.value.into_owned())
                .map(Some)
                .map_err(|error| {
                    format!("libvirt domain XML attribute is invalid UTF-8: {error}")
                });
        }
    }
    Ok(None)
}

fn virtual_media_target_ownership(
    xml: &str,
    device_id: &str,
    target: &str,
) -> Result<TargetOwnership, String> {
    let expected_alias = format!("ua-bmc-mock-vmedia-{device_id}");
    let mut reader = Reader::from_str(xml);
    let mut inside_disk = false;
    let mut disk_device = None;
    let mut disk_target = None;
    let mut disk_bus = None;
    let mut disk_alias = None;
    let mut ownership = TargetOwnership::Missing;

    loop {
        let event = reader
            .read_event()
            .map_err(|error| format!("could not parse libvirt domain XML: {error}"))?;
        match event {
            Event::Start(element) if element.name().as_ref() == b"disk" => {
                inside_disk = true;
                disk_device = xml_attribute(&element, b"device")?;
                disk_target = None;
                disk_bus = None;
                disk_alias = None;
            }
            Event::Start(element) | Event::Empty(element)
                if inside_disk && element.name().as_ref() == b"target" =>
            {
                disk_target = xml_attribute(&element, b"dev")?;
                disk_bus = xml_attribute(&element, b"bus")?;
            }
            Event::Start(element) | Event::Empty(element)
                if inside_disk && element.name().as_ref() == b"alias" =>
            {
                disk_alias = xml_attribute(&element, b"name")?;
            }
            Event::End(element) if element.name().as_ref() == b"disk" => {
                if disk_target.as_deref() == Some(target) {
                    if ownership != TargetOwnership::Missing {
                        return Err(format!(
                            "libvirt domain has more than one disk at target {target}"
                        ));
                    }
                    ownership = if disk_device.as_deref() == Some("cdrom")
                        && disk_bus.as_deref() == Some("sata")
                        && disk_alias.as_deref() == Some(expected_alias.as_str())
                    {
                        TargetOwnership::Owned
                    } else {
                        TargetOwnership::Foreign {
                            device: disk_device.take(),
                            bus: disk_bus.take(),
                            alias: disk_alias.take(),
                        }
                    };
                }
                inside_disk = false;
            }
            Event::Eof => break,
            _ => {}
        }
    }
    Ok(ownership)
}

enum MediaSource {
    File(PathBuf),
    Network {
        protocol: String,
        host: String,
        port: u16,
        path: String,
    },
}

impl MediaSource {
    fn parse(image: &str) -> Result<Self, VirtualMediaError> {
        let Ok(url) = Url::parse(image) else {
            return Ok(Self::File(PathBuf::from(image)));
        };
        match url.scheme() {
            "file" => url
                .to_file_path()
                .map(Self::File)
                .map_err(|()| VirtualMediaError::BadRequest(format!("invalid file URL: {image}"))),
            "http" | "https" => {
                if url.username() != "" || url.password().is_some() || url.query().is_some() {
                    return Err(VirtualMediaError::BadRequest(
                        "virtual media URLs must not contain credentials or a query".to_string(),
                    ));
                }
                let host = url.host_str().ok_or_else(|| {
                    VirtualMediaError::BadRequest(format!("virtual media URL has no host: {image}"))
                })?;
                Ok(Self::Network {
                    protocol: url.scheme().to_string(),
                    host: host.to_string(),
                    port: url
                        .port_or_known_default()
                        .expect("HTTP(S) has a default port"),
                    path: url.path().to_string(),
                })
            }
            scheme => Err(VirtualMediaError::BadRequest(format!(
                "unsupported virtual media URL scheme: {scheme}"
            ))),
        }
    }
}

fn virtual_media_xml(
    device_id: &str,
    target: &str,
    image: &str,
    write_protected: bool,
) -> Result<String, VirtualMediaError> {
    let mut writer = Writer::new(Vec::new());
    let mut disk = BytesStart::new("disk");
    let source = MediaSource::parse(image)?;
    disk.push_attribute((
        "type",
        match &source {
            MediaSource::File(_) => "file",
            MediaSource::Network { .. } => "network",
        },
    ));
    disk.push_attribute(("device", "cdrom"));
    writer.write_event(Event::Start(disk)).unwrap();

    let mut driver = BytesStart::new("driver");
    driver.push_attribute(("name", "qemu"));
    driver.push_attribute(("type", "raw"));
    writer.write_event(Event::Empty(driver)).unwrap();

    match source {
        MediaSource::File(path) => {
            let mut source = BytesStart::new("source");
            let path = path.to_string_lossy();
            source.push_attribute(("file", path.as_ref()));
            writer.write_event(Event::Empty(source)).unwrap();
        }
        MediaSource::Network {
            protocol,
            host,
            port,
            path,
        } => {
            let mut source = BytesStart::new("source");
            source.push_attribute(("protocol", protocol.as_str()));
            source.push_attribute(("name", path.as_str()));
            writer.write_event(Event::Start(source)).unwrap();
            let mut host_element = BytesStart::new("host");
            let port = port.to_string();
            host_element.push_attribute(("name", host.as_str()));
            host_element.push_attribute(("port", port.as_str()));
            writer.write_event(Event::Empty(host_element)).unwrap();
            writer
                .write_event(Event::End(BytesEnd::new("source")))
                .unwrap();
        }
    }

    let mut target_element = BytesStart::new("target");
    target_element.push_attribute(("dev", target));
    target_element.push_attribute(("bus", "sata"));
    writer.write_event(Event::Empty(target_element)).unwrap();
    if write_protected {
        writer
            .write_event(Event::Empty(BytesStart::new("readonly")))
            .unwrap();
    }
    let mut alias = BytesStart::new("alias");
    let alias_name = format!("ua-bmc-mock-vmedia-{device_id}");
    alias.push_attribute(("name", alias_name.as_str()));
    writer.write_event(Event::Empty(alias)).unwrap();
    writer
        .write_event(Event::End(BytesEnd::new("disk")))
        .unwrap();

    String::from_utf8(writer.into_inner()).map_err(|error| {
        VirtualMediaError::Command(format!("generated device XML is invalid UTF-8: {error}"))
    })
}

fn empty_virtual_media_xml(device_id: &str, target: &str) -> Result<String, VirtualMediaError> {
    let mut writer = Writer::new(Vec::new());
    let mut disk = BytesStart::new("disk");
    disk.push_attribute(("type", "file"));
    disk.push_attribute(("device", "cdrom"));
    writer.write_event(Event::Start(disk)).unwrap();

    let mut driver = BytesStart::new("driver");
    driver.push_attribute(("name", "qemu"));
    driver.push_attribute(("type", "raw"));
    writer.write_event(Event::Empty(driver)).unwrap();

    let mut target_element = BytesStart::new("target");
    target_element.push_attribute(("dev", target));
    target_element.push_attribute(("bus", "sata"));
    writer.write_event(Event::Empty(target_element)).unwrap();
    writer
        .write_event(Event::Empty(BytesStart::new("readonly")))
        .unwrap();
    let mut alias = BytesStart::new("alias");
    let alias_name = format!("ua-bmc-mock-vmedia-{device_id}");
    alias.push_attribute(("name", alias_name.as_str()));
    writer.write_event(Event::Empty(alias)).unwrap();
    writer
        .write_event(Event::End(BytesEnd::new("disk")))
        .unwrap();

    String::from_utf8(writer.into_inner()).map_err(|error| {
        VirtualMediaError::Command(format!("generated device XML is invalid UTF-8: {error}"))
    })
}

#[cfg(test)]
mod tests {
    use std::borrow::Cow;
    use std::fs;
    use std::sync::Arc;

    use axum::Router;
    use axum::body::Body;
    use axum::http::{Method, Request, StatusCode};
    use serde_json::json;
    use tower::ServiceExt;

    use super::*;
    use crate::test_support::host_info;
    use crate::{HardwareType, MachineRouterOptions, VirtualMediaDeviceConfig, machine_router};

    async fn request(
        router: &Router,
        method: Method,
        uri: &str,
        body: serde_json::Value,
    ) -> StatusCode {
        let response = router
            .clone()
            .oneshot(
                Request::builder()
                    .method(method)
                    .uri(uri)
                    .header("content-type", "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        response.status()
    }

    #[test]
    fn replaces_domain_boot_order() {
        let xml = "<domain><os><type>hvm</type><boot dev='hd'/></os><devices/></domain>";
        let actual = set_boot_order_xml(xml, &["cdrom", "hd"]).unwrap();

        assert!(actual.contains("<type>hvm</type>"));
        assert!(actual.contains("<boot dev=\"cdrom\"/><boot dev=\"hd\"/>"));
        assert!(!actual.contains("<boot dev='hd'/>"));
    }

    #[test]
    fn builds_http_virtual_media_device() {
        let actual =
            virtual_media_xml("Cd", "sdb", "http://127.0.0.1:8080/installer.iso", true).unwrap();

        assert!(actual.contains("<disk type=\"network\" device=\"cdrom\">"));
        assert!(actual.contains("<source protocol=\"http\" name=\"/installer.iso\">"));
        assert!(actual.contains("<host name=\"127.0.0.1\" port=\"8080\"/>"));
        assert!(actual.contains("<target dev=\"sdb\" bus=\"sata\"/>"));
        assert!(actual.contains("<readonly/>"));
    }

    #[test]
    fn builds_file_virtual_media_device() {
        let actual = virtual_media_xml("ConfigCd", "sdc", "/tmp/config.iso", false).unwrap();

        assert!(actual.contains("<disk type=\"file\" device=\"cdrom\">"));
        assert!(actual.contains("<source file=\"/tmp/config.iso\"/>"));
        assert!(actual.contains("<target dev=\"sdc\" bus=\"sata\"/>"));
        assert!(!actual.contains("<readonly/>"));
    }

    #[test]
    fn classifies_virtual_media_target_ownership() {
        let cases = [
            (
                "missing",
                "<domain><devices/></domain>",
                TargetOwnership::Missing,
            ),
            (
                "owned",
                "<domain><devices><disk device='cdrom'><target dev='sdc' bus='sata'/><alias name='ua-bmc-mock-vmedia-ConfigCd'/></disk></devices></domain>",
                TargetOwnership::Owned,
            ),
            (
                "foreign",
                "<domain><devices><disk device='disk'><target dev='sdc' bus='scsi'/><alias name='ua-data'/></disk></devices></domain>",
                TargetOwnership::Foreign {
                    device: Some("disk".to_string()),
                    bus: Some("scsi".to_string()),
                    alias: Some("ua-data".to_string()),
                },
            ),
        ];

        for (name, xml, expected) in cases {
            assert_eq!(
                virtual_media_target_ownership(xml, "ConfigCd", "sdc").unwrap(),
                expected,
                "{name}"
            );
        }
    }

    fn test_router(callbacks: Arc<LibvirtCallbacks>) -> (Router, BmcState) {
        machine_router(
            &host_info(HardwareType::DellPowerEdgeR750),
            callbacks,
            "test-host-id".to_string(),
            false,
            MachineRouterOptions {
                bmc_reset_duration: None,
                virtual_media_devices: Some(vec![VirtualMediaDeviceConfig {
                    id: Cow::Borrowed("Cd"),
                    name: Cow::Borrowed("Operating System Virtual CD"),
                    media_types: vec![Cow::Borrowed("CD"), Cow::Borrowed("DVD")],
                }]),
            },
        )
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn updates_an_owned_cdrom_in_place_for_live_and_persistent_state() {
        use std::os::unix::fs::PermissionsExt;

        let directory = tempfile::tempdir().unwrap();
        let virsh_path = directory.path().join("virsh");
        let log_path = directory.path().join("virsh.log");
        let persistent_xml_path = directory.path().join("persistent.xml");
        let live_xml_path = directory.path().join("live.xml");
        let defined_xml_path = directory.path().join("defined.xml");
        let inserted_xml_path = directory.path().join("inserted.xml");
        fs::write(
            &persistent_xml_path,
            "<domain><os><type>hvm</type><boot dev='hd'/></os><devices/></domain>",
        )
        .unwrap();
        let script = format!(
            r#"#!/bin/sh
printf '%s\n' "$*" >> '{}'
case "$3" in
  domstate)
    if [ -f '{}' ]; then printf 'running\n'; else printf 'shut off\n'; fi
    ;;
  dumpxml)
    if [ "$4" = "--inactive" ]; then cat '{}'; else cat '{}'; fi
    ;;
  attach-device)
    {{
      printf '<domain><os><type>hvm</type><boot dev="hd"/></os><devices>'
      cat "$5"
      printf '</devices></domain>\n'
    }} > '{}.new'
    mv '{}.new' '{}'
    ;;
  update-device)
    if grep -q '<source' "$5"; then cp "$5" '{}'; fi
    {{
      printf '<domain><os><type>hvm</type><boot dev="hd"/></os><devices>'
      cat "$5"
      printf '</devices></domain>\n'
    }} > '{}.new'
    mv '{}.new' '{}'
    case "$*" in *--live*) cp '{}' '{}' ;; esac
    ;;
  define)
    cp "$4" '{}'
    cp "$4" '{}'
    ;;
  start)
    touch '{}'
    cp '{}' '{}'
    ;;
esac
"#,
            log_path.display(),
            directory.path().join("running").display(),
            persistent_xml_path.display(),
            live_xml_path.display(),
            persistent_xml_path.display(),
            persistent_xml_path.display(),
            persistent_xml_path.display(),
            inserted_xml_path.display(),
            persistent_xml_path.display(),
            persistent_xml_path.display(),
            persistent_xml_path.display(),
            persistent_xml_path.display(),
            live_xml_path.display(),
            defined_xml_path.display(),
            persistent_xml_path.display(),
            directory.path().join("running").display(),
            persistent_xml_path.display(),
            live_xml_path.display(),
        );
        fs::write(&virsh_path, script).unwrap();
        let mut permissions = fs::metadata(&virsh_path).unwrap().permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(&virsh_path, permissions).unwrap();

        let callbacks = Arc::new(LibvirtCallbacks::new(Config {
            virsh_path,
            uri: "qemu:///system".to_string(),
            domain: "dsx-node".to_string(),
            virtual_media_targets: BTreeMap::from([("Cd".to_string(), "sdb".to_string())]),
        }));
        let (router, state) = test_router(callbacks.clone());
        callbacks.bind_state(&state).unwrap();
        let system = "/redfish/v1/Systems/System.Embedded.1";

        let status = request(
            &router,
            Method::PATCH,
            system,
            json!({
                "Boot": {
                    "BootSourceOverrideEnabled": "Once",
                    "BootSourceOverrideTarget": "Cd",
                }
            }),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let status = request(
            &router,
            Method::POST,
            &format!("{system}/Actions/ComputerSystem.Reset"),
            json!({"ResetType": "On"}),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let status = request(
            &router,
            Method::POST,
            &format!("{system}/VirtualMedia/Cd/Actions/VirtualMedia.InsertMedia"),
            json!({
                "Image": "http://127.0.0.1:8080/installer.iso",
                "WriteProtected": true,
            }),
        )
        .await;
        assert_eq!(status, StatusCode::NO_CONTENT);
        let status = request(
            &router,
            Method::POST,
            &format!("{system}/VirtualMedia/Cd/Actions/VirtualMedia.EjectMedia"),
            json!({}),
        )
        .await;
        assert_eq!(status, StatusCode::NO_CONTENT);
        let status = request(
            &router,
            Method::PATCH,
            system,
            json!({
                "Boot": {
                    "BootSourceOverrideMode": "UEFI",
                    "BootSourceOverrideEnabled": "Disabled",
                    "BootSourceOverrideTarget": "None",
                }
            }),
        )
        .await;
        assert_eq!(status, StatusCode::OK);

        let log = fs::read_to_string(log_path).unwrap();
        assert!(log.contains("--connect qemu:///system dumpxml --inactive dsx-node"));
        assert!(log.contains("--connect qemu:///system start dsx-node"));
        assert!(log.contains("--connect qemu:///system attach-device dsx-node"));
        assert!(log.contains("--config"));
        assert!(log.contains("--live --config"));
        assert!(log.contains("--connect qemu:///system update-device dsx-node"));
        assert!(!log.contains("detach-disk"));
        let inserted_xml = fs::read_to_string(inserted_xml_path).unwrap();
        assert!(inserted_xml.contains("protocol=\"http\""));
        assert!(inserted_xml.contains("dev=\"sdb\""));
        assert!(inserted_xml.contains("alias name=\"ua-bmc-mock-vmedia-Cd\""));
        let defined_xml = fs::read_to_string(defined_xml_path).unwrap();
        assert!(defined_xml.contains("<boot dev=\"hd\"/>"));
        assert!(!defined_xml.contains("<boot dev=\"cdrom\"/>"));
    }

    #[cfg(unix)]
    #[test]
    fn refuses_to_claim_a_foreign_disk_at_the_configured_target() {
        use std::os::unix::fs::PermissionsExt;

        let directory = tempfile::tempdir().unwrap();
        let virsh_path = directory.path().join("virsh");
        let log_path = directory.path().join("virsh.log");
        let script = format!(
            r#"#!/bin/sh
printf '%s\n' "$*" >> '{}'
case "$3" in
  dumpxml) printf '<domain><devices><disk device="disk"><target dev="sdb" bus="scsi"/><alias name="ua-data"/></disk></devices></domain>\n' ;;
esac
"#,
            log_path.display(),
        );
        fs::write(&virsh_path, script).unwrap();
        let mut permissions = fs::metadata(&virsh_path).unwrap().permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(&virsh_path, permissions).unwrap();

        let callbacks = Arc::new(LibvirtCallbacks::new(Config {
            virsh_path,
            uri: "qemu:///system".to_string(),
            domain: "dsx-node".to_string(),
            virtual_media_targets: BTreeMap::from([("Cd".to_string(), "sdb".to_string())]),
        }));
        let (_, state) = test_router(callbacks.clone());

        let error = callbacks.bind_state(&state).unwrap_err();
        assert!(error.contains("refusing to claim libvirt target sdb"));
        let log = fs::read_to_string(log_path).unwrap();
        assert!(!log.contains("detach-disk"));
        assert!(!log.contains("update-device"));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn failed_media_update_returns_an_error_and_restores_redfish_state() {
        use std::os::unix::fs::PermissionsExt;

        use http_body_util::BodyExt;

        let directory = tempfile::tempdir().unwrap();
        let virsh_path = directory.path().join("virsh");
        let xml_path = directory.path().join("domain.xml");
        fs::write(
            &xml_path,
            "<domain><devices><disk type='file' device='cdrom'><driver name='qemu' type='raw'/><target dev='sdb' bus='sata'/><readonly/><alias name='ua-bmc-mock-vmedia-Cd'/></disk></devices></domain>",
        )
        .unwrap();
        let script = format!(
            r#"#!/bin/sh
case "$3" in
  domstate) printf 'shut off\n' ;;
  dumpxml) cat '{}' ;;
  update-device)
    if grep -q '<source' "$5"; then printf 'injected update failure\n' >&2; exit 1; fi
    cp "$5" '{}'
    ;;
esac
"#,
            xml_path.display(),
            xml_path.display(),
        );
        fs::write(&virsh_path, script).unwrap();
        let mut permissions = fs::metadata(&virsh_path).unwrap().permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(&virsh_path, permissions).unwrap();

        let callbacks = Arc::new(LibvirtCallbacks::new(Config {
            virsh_path,
            uri: "qemu:///system".to_string(),
            domain: "dsx-node".to_string(),
            virtual_media_targets: BTreeMap::from([("Cd".to_string(), "sdb".to_string())]),
        }));
        let (router, state) = test_router(callbacks.clone());
        callbacks.bind_state(&state).unwrap();
        let media = "/redfish/v1/Systems/System.Embedded.1/VirtualMedia/Cd";

        let status = request(
            &router,
            Method::POST,
            &format!("{media}/Actions/VirtualMedia.InsertMedia"),
            json!({"Image": "/tmp/config.iso"}),
        )
        .await;
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);

        let response = router
            .oneshot(Request::builder().uri(media).body(Body::empty()).unwrap())
            .await
            .unwrap();
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(body["Inserted"], false);
        assert_eq!(body["Image"], serde_json::Value::Null);
    }
}
