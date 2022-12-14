#[macro_use]
extern crate serde_derive;

pub mod bios;
pub mod common;
pub mod manager;
pub mod power;
pub mod storage;
pub mod system;
pub mod thermal;

use crate::common::{
    EnabledDisabled, OnOff, RedfishSettingsApplyTime, SetOemDellSettingsApplyTime,
};
use reqwest::{
    blocking::Client, blocking::ClientBuilder, header::HeaderValue, header::ACCEPT,
    header::CONTENT_TYPE,
};
use serde::de::DeserializeOwned;
use serde::Serialize;
use std::collections::HashMap;
use std::time::Duration;

const REDFISH_ENDPOINT: &str = "redfish/v1";

pub enum Vendor {
    Dell,
    Hpe,
    Lenovo,
    Supermicro,
    Unknown,
}

pub struct Config {
    pub user: Option<String>,
    pub endpoint: String,
    pub password: Option<String>,
    pub port: Option<u16>,
    pub system: String,
    pub manager: String,
    pub vendor: Vendor,
}

pub struct Redfish {
    pub client: Client,
    pub config: Config,
}

impl Redfish {
    pub fn new(conf: Config) -> Self {
        let timeout = Duration::from_secs(5);
        let builder = ClientBuilder::new();
        let c = builder
            .danger_accept_invalid_certs(true)
            .timeout(timeout)
            .build()
            .unwrap();
        Redfish {
            client: c,
            config: conf,
        }
    }

    fn get<T>(&self, api: &str) -> Result<T, reqwest::Error>
    where
        T: DeserializeOwned + ::std::fmt::Debug,
    {
        let url = match self.config.port {
            Some(p) => format!(
                "https://{}:{}/{}/{}",
                self.config.endpoint, p, REDFISH_ENDPOINT, api
            ),
            None => format!(
                "https://{}/{}/{}",
                self.config.endpoint, REDFISH_ENDPOINT, api
            ),
        };

        let res: T = match &self.config.user {
            Some(user) => self
                .client
                .get(&url)
                .header(ACCEPT, HeaderValue::from_static("application/json"))
                .header(CONTENT_TYPE, HeaderValue::from_static("application/json"))
                .basic_auth(user, self.config.password.as_ref())
                .send()?
                .error_for_status()?
                .json()?,
            None => self
                .client
                .get(&url)
                .header(ACCEPT, HeaderValue::from_static("application/json"))
                .header(CONTENT_TYPE, HeaderValue::from_static("application/json"))
                .send()?
                .error_for_status()?
                .json()?,
        };
        Ok(res)
    }

    fn post(&self, api: &str, data: HashMap<&str, String>) -> Result<(), reqwest::Error> {
        let url = match self.config.port {
            Some(p) => format!(
                "https://{}:{}/{}/{}",
                self.config.endpoint, p, REDFISH_ENDPOINT, api
            ),
            None => format!(
                "https://{}/{}/{}",
                self.config.endpoint, REDFISH_ENDPOINT, api
            ),
        };

        match &self.config.user {
            Some(user) => self
                .client
                .post(&url)
                .header(ACCEPT, HeaderValue::from_static("application/json"))
                .header(CONTENT_TYPE, HeaderValue::from_static("application/json"))
                .basic_auth(user, self.config.password.as_ref())
                .json(&data)
                .send()?
                .error_for_status()?,
            None => self
                .client
                .post(&url)
                .header(ACCEPT, HeaderValue::from_static("application/json"))
                .header(CONTENT_TYPE, HeaderValue::from_static("application/json"))
                .json(&data)
                .send()?
                .error_for_status()?,
        };
        Ok(())
    }

    fn patch<T>(&self, api: &str, data: T) -> Result<(), reqwest::Error>
    where
        T: Serialize + ::std::fmt::Debug,
    {
        let url = match self.config.port {
            Some(p) => format!(
                "https://{}:{}/{}/{}",
                self.config.endpoint, p, REDFISH_ENDPOINT, api
            ),
            None => format!(
                "https://{}/{}/{}",
                self.config.endpoint, REDFISH_ENDPOINT, api
            ),
        };

        match &self.config.user {
            Some(user) => self
                .client
                .patch(&url)
                .header(ACCEPT, HeaderValue::from_static("application/json"))
                .header(CONTENT_TYPE, HeaderValue::from_static("application/json"))
                .basic_auth(user, self.config.password.as_ref())
                .json(&data)
                .send()?
                .error_for_status()?,
            None => self
                .client
                .patch(&url)
                .header(ACCEPT, HeaderValue::from_static("application/json"))
                .header(CONTENT_TYPE, HeaderValue::from_static("application/json"))
                .json(&data)
                .send()?
                .error_for_status()?,
        };
        Ok(())
    }

    pub fn get_system_id(&mut self) -> Result<(), reqwest::Error> {
        let url = "Systems/";
        match self.get(url) {
            Ok(x) => {
                let systems: system::Systems = x;
                if systems.members.is_empty() {
                    self.config.system = "1".to_string(); // default to dmtf standard suggested
                    return Ok(());
                }
                let v: Vec<&str> = systems.members[0].odata_id.split('/').collect();
                self.config.system = v.last().unwrap().to_string();
                if self.config.system == "System.Embedded.1" {
                    self.config.vendor = Vendor::Dell
                }
            }
            Err(e) => return Err(e),
        }
        Ok(())
    }

    pub fn get_manager_id(&mut self) -> Result<(), reqwest::Error> {
        let url = "Managers/";
        match self.get(url) {
            Ok(x) => {
                let bmcs: manager::Managers = x;
                if bmcs.members.is_empty() {
                    self.config.manager = "1".to_string(); // default to dmtf standard suggested
                    return Ok(());
                }
                let v: Vec<&str> = bmcs.members[0].odata_id.split('/').collect();
                self.config.manager = v.last().unwrap().to_string();
            }
            Err(e) => return Err(e),
        }
        Ok(())
    }

    pub fn get_system(&self) -> Result<system::ComputerSystem, reqwest::Error> {
        let url = format!("Systems/{}/", self.config.system);
        let host: system::ComputerSystem = self.get(&url)?;
        Ok(host)
    }

    pub fn set_system_power(
        &self,
        action: system::SystemPowerControl,
    ) -> Result<(), reqwest::Error> {
        let url = format!(
            "Systems/{}/Actions/ComputerSystem.Reset",
            self.config.system
        );
        let mut arg = HashMap::new();
        arg.insert("ResetType", action.to_string());
        self.post(&url, arg)
    }

    pub fn get_bios_data(&self) -> Result<bios::OemDellBios, reqwest::Error> {
        let url = format!("Systems/{}/Bios", self.config.system);
        let bios: bios::OemDellBios = self.get(&url)?;
        Ok(bios)
    }

    pub fn get_bmc_data(&self) -> Result<manager::OemDellAttributesResult, reqwest::Error> {
        let url = format!(
            "Managers/{}/Oem/Dell/DellAttributes/{}/",
            self.config.manager, self.config.manager
        );
        let bmc_attrs: manager::OemDellAttributesResult = self.get(&url)?;
        Ok(bmc_attrs)
    }

    pub fn set_bios_attribute(
        &self,
        attribute: String,
        value: String,
    ) -> Result<(), reqwest::Error> {
        let url = format!("Systems/{}/Bios/Settings/", self.config.system);
        let attr = format!("{{\"@Redfish.SettingsApplyTime\": {{\"ApplyTime\": \"OnReset\"}},\"Attributes\": {{\"{}\":\"{}\"}}}}", attribute, value);
        self.patch(&url, attr)
    }

    pub fn enable_bios_lockdown(&self) -> Result<(), reqwest::Error> {
        let apply_time = SetOemDellSettingsApplyTime {
            apply_time: RedfishSettingsApplyTime::OnReset, // requires reboot to apply
        };
        let lockdown = bios::OemDellBiosLockdownAttrs {
            in_band_manageability_interface: EnabledDisabled::Disabled,
            uefi_variable_access: bios::UefiVariableAccessSettings::Controlled,
        };
        let set_lockdown_attrs = bios::SetOemDellBiosLockdownAttrs {
            redfish_settings_apply_time: apply_time,
            attributes: lockdown,
        };
        let url = format!("Systems/{}/Bios/Settings/", self.config.system);
        self.patch(&url, set_lockdown_attrs)
    }

    pub fn disable_bios_lockdown(&self) -> Result<(), reqwest::Error> {
        let apply_time = SetOemDellSettingsApplyTime {
            apply_time: RedfishSettingsApplyTime::OnReset, // requires reboot to apply
        };
        let lockdown = bios::OemDellBiosLockdownAttrs {
            in_band_manageability_interface: EnabledDisabled::Enabled,
            uefi_variable_access: bios::UefiVariableAccessSettings::Standard,
        };
        let set_lockdown_attrs = bios::SetOemDellBiosLockdownAttrs {
            redfish_settings_apply_time: apply_time,
            attributes: lockdown,
        };
        let url = format!("Systems/{}/Bios/Settings/", self.config.system);
        self.patch(&url, set_lockdown_attrs)
    }

    pub fn setup_serial_console(&self) -> Result<(), reqwest::Error> {
        let apply_time = SetOemDellSettingsApplyTime {
            apply_time: RedfishSettingsApplyTime::OnReset, // requires reboot to apply
        };
        let serial_console = bios::OemDellBiosSerialAttrs {
            serial_comm: bios::SerialCommSettings::OnConRedir,
            serial_port_address: bios::SerialPortSettings::Com1,
            ext_serial_connector: bios::SerialPortExtSettings::Serial1,
            fail_safe_baud: "115200".to_string(),
            con_term_type: bios::SerialPortTermSettings::Vt100Vt220,
            redir_after_boot: EnabledDisabled::Enabled,
        };
        let set_serial_attrs = bios::SetOemDellBiosSerialAttrs {
            redfish_settings_apply_time: apply_time,
            attributes: serial_console,
        };

        let url = format!("Systems/{}/Bios/Settings/", self.config.system);
        self.patch(&url, set_serial_attrs)
    }

    pub fn enable_tpm(&self) -> Result<(), reqwest::Error> {
        let apply_time = SetOemDellSettingsApplyTime {
            apply_time: RedfishSettingsApplyTime::OnReset, // requires reboot to apply
        };
        let tpm = bios::OemDellBiosTpmAttrs {
            tpm_security: OnOff::On,
            tpm2_hierarchy: bios::Tpm2HierarchySettings::Enabled,
        };
        let set_tpm_enabled = bios::SetOemDellBiosTpmAttrs {
            redfish_settings_apply_time: apply_time,
            attributes: tpm,
        };
        let url = format!("Systems/{}/Bios/Settings/", self.config.system);
        self.patch(&url, set_tpm_enabled)
    }

    /// make sure the tpm is enabled after clear and reboot
    pub fn reset_tpm(&self) -> Result<(), reqwest::Error> {
        let apply_time = SetOemDellSettingsApplyTime {
            apply_time: RedfishSettingsApplyTime::OnReset,
        };
        let tpm = bios::OemDellBiosTpmAttrs {
            tpm_security: OnOff::On,
            tpm2_hierarchy: bios::Tpm2HierarchySettings::Clear,
        };
        let set_tpm_clear = bios::SetOemDellBiosTpmAttrs {
            redfish_settings_apply_time: apply_time,
            attributes: tpm,
        };
        let url = format!("Systems/{}/Bios/Settings/", self.config.system);
        self.patch(&url, set_tpm_clear)
    }

    pub fn disable_tpm(&self) -> Result<(), reqwest::Error> {
        let apply_time = SetOemDellSettingsApplyTime {
            apply_time: RedfishSettingsApplyTime::OnReset, // requires reboot to apply
        };
        let tpm = bios::OemDellBiosTpmAttrs {
            tpm_security: OnOff::Off,
            tpm2_hierarchy: bios::Tpm2HierarchySettings::Disabled,
        };
        let set_tpm_disabled = bios::SetOemDellBiosTpmAttrs {
            redfish_settings_apply_time: apply_time,
            attributes: tpm,
        };
        let url = format!("Systems/{}/Bios/Settings/", self.config.system);
        self.patch(&url, set_tpm_disabled)
    }

    pub fn enable_bmc_lockdown(
        &self,
        entry: manager::OemDellBootDevices,
        once: bool,
    ) -> Result<(), reqwest::Error> {
        let apply_time = SetOemDellSettingsApplyTime {
            apply_time: RedfishSettingsApplyTime::OnReset,
        };
        let boot_entry = manager::OemDellServerBoot {
            first_boot_device: entry,
            boot_once: if once {
                EnabledDisabled::Enabled
            } else {
                EnabledDisabled::Disabled
            },
        };
        let lockdown = manager::OemDellBmcLockdown {
            system_lockdown: EnabledDisabled::Enabled,
            racadm_enable: EnabledDisabled::Disabled,
            server_boot: boot_entry,
        };
        let set_bmc_lockdown = manager::SetOemDellBmcLockdown {
            redfish_settings_apply_time: apply_time,
            attributes: lockdown,
        };
        let url = format!("Managers/{}/Attributes", self.config.manager);
        self.patch(&url, set_bmc_lockdown)
    }

    pub fn disable_bmc_lockdown(
        &self,
        entry: manager::OemDellBootDevices,
        once: bool,
    ) -> Result<(), reqwest::Error> {
        let apply_time = SetOemDellSettingsApplyTime {
            apply_time: RedfishSettingsApplyTime::Immediate, // bmc settings don't require reboot
        };
        let boot_entry = manager::OemDellServerBoot {
            first_boot_device: entry,
            boot_once: if once {
                EnabledDisabled::Enabled
            } else {
                EnabledDisabled::Disabled
            },
        };
        let lockdown = manager::OemDellBmcLockdown {
            system_lockdown: EnabledDisabled::Disabled,
            racadm_enable: EnabledDisabled::Enabled,
            server_boot: boot_entry,
        };
        let set_bmc_lockdown = manager::SetOemDellBmcLockdown {
            redfish_settings_apply_time: apply_time,
            attributes: lockdown,
        };
        let url = format!("Managers/{}/Attributes", self.config.manager);
        self.patch(&url, set_bmc_lockdown)
    }

    pub fn setup_bmc_remote_access(&self) -> Result<(), reqwest::Error> {
        let apply_time = SetOemDellSettingsApplyTime {
            apply_time: RedfishSettingsApplyTime::Immediate,
        };
        let serial_redirect = manager::OemDellSerialRedirection {
            enable: EnabledDisabled::Enabled,
            quit_key: "~~.".to_string(),
        };
        let ipmi_sol_settings = manager::OemDellIpmiSol {
            enable: EnabledDisabled::Enabled,
            baud_rate: "11500".to_string(),
            min_privilege: "Administrator".to_string(),
        };
        let remote_access = manager::OemDellBmcRemoteAccess {
            ssh_enable: EnabledDisabled::Enabled,
            serial_redirection: serial_redirect,
            ipmi_lan_enable: EnabledDisabled::Enabled,
            ipmi_sol: ipmi_sol_settings,
        };
        let set_remote_access = manager::SetOemDellBmcRemoteAccess {
            redfish_settings_apply_time: apply_time,
            attributes: remote_access,
        };
        let url = format!("Managers/{}/Attributes", self.config.manager);
        self.patch(&url, set_remote_access)
    }

    pub fn get_boot_options(&self) -> Result<system::BootOptions, reqwest::Error> {
        let url = format!("Systems/{}/BootOptions", self.config.system);
        let boot_options: system::BootOptions = self.get(&url)?;
        Ok(boot_options)
    }

    pub fn set_boot_first(
        &self,
        entry: manager::OemDellBootDevices,
        once: bool,
    ) -> Result<(), reqwest::Error> {
        let apply_time = SetOemDellSettingsApplyTime {
            apply_time: RedfishSettingsApplyTime::OnReset,
        };
        let boot_entry = manager::OemDellServerBoot {
            first_boot_device: entry,
            boot_once: if once {
                EnabledDisabled::Enabled
            } else {
                EnabledDisabled::Disabled
            },
        };
        let boot = manager::OemDellServerBootAttrs {
            server_boot: boot_entry,
        };
        let set_boot = manager::SetOemDellFirstBootDevice {
            redfish_settings_apply_time: apply_time,
            attributes: boot,
        };
        let url = format!("Managers/{}/Attributes", self.config.manager);
        self.patch(&url, set_boot)
    }

    pub fn get_array_controller(
        &self,
        controller_id: u64,
    ) -> Result<storage::ArrayController, reqwest::Error> {
        let url = format!(
            "Systems/{}/SmartStorage/ArrayControllers/{}/",
            self.config.system, controller_id
        );
        let s: storage::ArrayController = self.get(&url)?;
        Ok(s)
    }
    pub fn get_array_controllers(&self) -> Result<storage::ArrayControllers, reqwest::Error> {
        let url = format!(
            "Systems/{}/SmartStorage/ArrayControllers/",
            self.config.system
        );
        let s: storage::ArrayControllers = self.get(&url)?;
        Ok(s)
    }

    /// Query the manager status from the server
    pub fn get_manager_status(&self) -> Result<manager::ManagerDell, reqwest::Error> {
        let url = format!("Managers/{}", self.config.manager);
        let m: manager::ManagerDell = self.get(&url)?;
        Ok(m)
    }

    /// Query the power status from the server
    pub fn get_power_status(&self) -> Result<power::Power, reqwest::Error> {
        let url = format!("Chassis/{}/Power/", self.config.system);
        let p: power::Power = self.get(&url)?;
        Ok(p)
    }

    /// Query the thermal status from the server
    pub fn get_thermal_status(&self) -> Result<thermal::Thermal, reqwest::Error> {
        let url = format!("Chassis/{}/Thermal/", self.config.system);
        let t: thermal::Thermal = self.get(&url)?;
        Ok(t)
    }

    /// Query the smart array status from the server
    pub fn get_smart_array_status(
        &self,
        controller_id: u64,
    ) -> Result<storage::SmartArray, reqwest::Error> {
        let url = format!(
            "Systems/{}/SmartStorage/ArrayControllers/{}/",
            self.config.system, controller_id
        );
        let s: storage::SmartArray = self.get(&url)?;
        Ok(s)
    }

    pub fn get_logical_drives(
        &self,
        controller_id: u64,
    ) -> Result<storage::LogicalDrives, reqwest::Error> {
        let url = format!(
            "Systems/{}/SmartStorage/ArrayControllers/{}/LogicalDrives/",
            self.config.system, controller_id
        );
        let s: storage::LogicalDrives = self.get(&url)?;
        Ok(s)
    }

    pub fn get_physical_drive(
        &self,
        drive_id: u64,
        controller_id: u64,
    ) -> Result<storage::DiskDrive, reqwest::Error> {
        let url = format!(
            "Systems/{}/SmartStorage/ArrayControllers/{}/DiskDrives/{}/",
            self.config.system, controller_id, drive_id,
        );
        let d: storage::DiskDrive = self.get(&url)?;
        Ok(d)
    }

    pub fn get_physical_drives(
        &self,
        controller_id: u64,
    ) -> Result<storage::DiskDrives, reqwest::Error> {
        let url = format!(
            "Systems/{}/SmartStorage/ArrayControllers/{}/DiskDrives/",
            self.config.system, controller_id
        );
        let d: storage::DiskDrives = self.get(&url)?;
        Ok(d)
    }

    pub fn get_storage_enclosures(
        &self,
        controller_id: u64,
    ) -> Result<storage::StorageEnclosures, reqwest::Error> {
        let url = format!(
            "Systems/{}/SmartStorage/ArrayControllers/{}/StorageEnclosures/",
            self.config.system, controller_id
        );
        let s: storage::StorageEnclosures = self.get(&url)?;
        Ok(s)
    }
    pub fn get_storage_enclosure(
        &self,
        controller_id: u64,
        enclosure_id: u64,
    ) -> Result<storage::StorageEnclosure, reqwest::Error> {
        let url = format!(
            "Systems/{}/SmartStorage/ArrayControllers/{}/StorageEnclosures/{}/",
            self.config.system, controller_id, enclosure_id,
        );
        let s: storage::StorageEnclosure = self.get(&url)?;
        Ok(s)
    }
}
