use std::fmt;
use std::fmt::Formatter;
use crate::common::*;

#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "PascalCase")]
pub struct OemDellBiosAttributes {
    pub system_model_name: String,
    pub system_bios_version: String,
    pub system_me_version: String,
    pub system_service_tag: String,
    pub system_manufacturer: String,
    pub sys_mfr_contact_info: String,
    pub system_cpld_version: String,
    pub uefi_compliance_version: String,
    pub proc_core_speed: String,
    pub proc_bus_speed: String,
    pub proc_1_id: String,
    pub proc_1_brand: String,
    pub proc_1_l2_cache: String,
    pub proc_1_l3_cache: String,
    pub proc_1_max_memory_capacity: String,
    pub proc_1_microcode: String,
    pub proc_2_id: String,
    pub proc_2_brand: String,
    pub proc_2_l2_cache: String,
    pub proc_2_l3_cache: String,
    pub proc_2_max_memory_capacity: String,
    pub proc_2_microcode: String,
    pub current_emb_video_state: String,
    pub aes_ni: String,
    pub tpm_info: String,
    pub tpm_firmware: String,
    pub sys_mem_size: String,
    pub sys_mem_type: String,
    pub sys_mem_speed: String,
    pub sys_mem_volt: String,
    pub video_mem: String,
    pub asset_tag: String,
    #[serde(rename = "SHA256SystemPassword")]
    pub sha256_system_password: String,
    #[serde(rename = "SHA256SystemPasswordSalt")]
    pub sha256_system_password_salt: String,
    #[serde(rename = "SHA256SetupPassword")]
    pub sha256_setup_password: String,
    #[serde(rename = "SHA256SetupPasswordSalt")]
    pub sha256_setup_password_salt: String,
    pub proc1_num_cores: i64,
    pub proc2_num_cores: i64,
    pub controlled_turbo_minus_bin: i64,
    pub logical_proc: String,
    pub cpu_interconnect_bus_speed: String,
    pub proc_virtualization: String,
    pub kernel_dma_protection: String,
    pub directory_mode: String,
    pub proc_adj_cache_line: String,
    pub proc_hw_prefetcher: String,
    pub dcu_streamer_prefetcher: String,
    pub dcu_ip_prefetcher: String,
    pub sub_numa_cluster: String,
    pub madt_core_enumeration: String,
    pub upi_prefetch: String,
    pub xpt_prefetch: String,
    pub llc_prefetch: String,
    pub dead_line_llc_alloc: String,
    pub dynamic_core_allocation: String,
    pub proc_avx_p1: String,
    pub processor_active_pbf: String,
    pub processor_rapl_prioritization: String,
    pub proc_x2_apic: String,
    pub avx_iccp_pre_grant_license: String,
    pub proc_cores: String,
    pub lmce_en: String,
    pub controlled_turbo: String,
    pub optimizer_mode: String,
    pub emb_sata: String,
    pub security_freeze_lock: String,
    pub write_cache: String,
    pub nvme_mode: String,
    pub bios_nvme_driver: String,
    pub boot_mode: String,
    pub boot_seq_retry: String,
    pub hdd_failover: String,
    pub generic_usb_boot: String,
    pub hdd_placeholder: String,
    pub sys_prep_clean: String,
    pub one_time_boot_mode: String,
    pub one_time_uefi_boot_seq_dev: String,
    pub pxe_dev1_en_dis: String,
    pub pxe_dev2_en_dis: String,
    pub pxe_dev3_en_dis: String,
    pub pxe_dev4_en_dis: String,
    pub pxe_dev1_interface: String,
    pub pxe_dev1_protocol: String,
    pub pxe_dev1_vlan_en_dis: String,
    pub pxe_dev2_interface: String,
    pub pxe_dev2_protocol: String,
    pub pxe_dev2_vlan_en_dis: String,
    pub pxe_dev3_interface: String,
    pub pxe_dev3_protocol: String,
    pub pxe_dev3_vlan_en_dis: String,
    pub pxe_dev4_interface: String,
    pub pxe_dev4_protocol: String,
    pub pxe_dev4_vlan_en_dis: String,
    pub usb_ports: String,
    pub usb_managed_port: String,
    pub emb_nic1_nic2: String,
    pub ioat_engine: String,
    pub emb_video: String,
    pub snoop_hld_off: String,
    pub sriov_global_enable: String,
    pub os_watchdog_timer: String,
    #[serde(rename = "PCIRootDeviceUnhide")]
    pub pci_root_device_unhide: String,
    pub mmio_above4_gb: String,
    #[serde(rename = "MemoryMappedIOH")]
    pub memory_mapped_ioh: String,
    pub dell_auto_discovery: String,
    pub serial_comm: String,
    pub serial_port_address: String,
    pub ext_serial_connector: String,
    pub fail_safe_baud: String,
    pub con_term_type: String,
    pub redir_after_boot: String,
    pub sys_profile: String,
    pub proc_pwr_perf: String,
    pub mem_frequency: String,
    pub proc_turbo_mode: String,
    #[serde(rename = "ProcC1E")]
    pub proc_c1e: String,
    #[serde(rename = "ProcCStates")]
    pub proc_cstates: String,
    pub mem_patrol_scrub: String,
    pub mem_refresh_rate: String,
    pub uncore_frequency: String,
    pub energy_performance_bias: String,
    pub monitor_mwait: String,
    pub workload_profile: String,
    pub cpu_interconnect_bus_link_power: String,
    pub pcie_aspm_l1: String,
    pub password_status: String,
    pub tpm_security: String,
    pub tpm2_hierarchy: String,
    pub intel_txt: String,
    pub memory_encryption: String,
    pub intel_sgx: String,
    pub pwr_button: String,
    pub ac_pwr_rcvry: String,
    pub ac_pwr_rcvry_delay: String,
    pub uefi_variable_access: String,
    pub in_band_manageability_interface: String,
    pub smm_security_mitigation: String,
    pub secure_boot: String,
    pub secure_boot_policy: String,
    pub secure_boot_mode: String,
    pub authorize_device_firmware: String,
    pub tpm_ppi_bypass_provision: String,
    pub tpm_ppi_bypass_clear: String,
    pub tpm2_algorithm: String,
    pub redundant_os_location: String,
    pub redundant_os_state: String,
    pub redundant_os_boot: String,
    pub mem_test: String,
    pub mem_op_mode: String,
    #[serde(rename = "FRMPercent")]
    pub frm_percent: String,
    pub node_interleave: String,
    pub memory_training: String,
    pub corr_ecc_smi: String,
    #[serde(rename = "CECriticalSEL")]
    pub ce_critical_sel: String,
    #[serde(rename = "PPROnUCE")]
    pub ppr_on_uce: String,
    pub num_lock: String,
    pub err_prompt: String,
    pub force_int10: String,
    #[serde(rename = "DellWyseP25BIOSAccess")]
    pub dell_wyse_p25_bios_access: String,
    pub power_cycle_request: String,
    pub sys_password: Option<String>,
    pub setup_password: Option<String>,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "PascalCase")]
pub struct OemDellSoftwareImage {
    pub software_images: Vec<ODataId>,
    pub active_software_image: ODataId
}

#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "PascalCase")]
pub struct OemDellBios {
    #[serde(rename = "@odata.context")]
    pub odata_context: String,
    #[serde(rename = "@odata.id")]
    pub odata_id: String,
    pub id: String,
    pub name: String,
    pub description: String,
    pub attribute_registry: String,
    pub attributes: OemDellBiosAttributes,
    pub links: OemDellSoftwareImage,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum RedfishSettingsApplyTime {
    AtMaintenanceWindowStart,
    Immediate,
    InMaintenanceWindowOnReset,
    OnReset,    // preferred
}

impl fmt::Display for RedfishSettingsApplyTime {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(self, f)
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "PascalCase")]
pub struct SetOemDellBiosSettingsApplyTime {
    pub apply_time: RedfishSettingsApplyTime,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum SerialCommSettings {
    OnConRedir,     // preferred
    OnNoConRedir,
    Off,
}

impl fmt::Display for SerialCommSettings {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(self, f)
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum SerialPortSettings {
    Com1,     // preferred
    Com2,
}

impl fmt::Display for SerialPortSettings {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(self, f)
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum SerialPortExtSettings {
    Serial1,     // preferred
    Serial2,
    RemoteAccDevice,
}

impl fmt::Display for SerialPortExtSettings {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(self, f)
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum SerialPortBaudSettings {
    Speed115200bps = 115200,     // preferred
    Speed57600bps = 57600,
    Speed19200bps = 19200,
    Speed9600bps = 9600,
}

impl fmt::Display for SerialPortBaudSettings {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(self, f)
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum SerialPortTermSettings {
    Vt100Vt220,     // preferred
    Ansi,
}

impl fmt::Display for SerialPortTermSettings {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(self, f)
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum EnabledDisabled {
    Enabled,
    Disabled,
}

impl fmt::Display for EnabledDisabled {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(self, f)
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum OnOff {
    On,
    Off,
}

impl fmt::Display for OnOff {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(self, f)
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "PascalCase")]
pub struct OemDellBiosSerialAttrs {
    pub serial_comm: SerialCommSettings,
    pub serial_port_address: SerialPortSettings,
    pub ext_serial_connector: SerialPortExtSettings,
    pub fail_safe_baud: String,
    pub con_term_type: SerialPortTermSettings,
    pub redir_after_boot: EnabledDisabled,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "PascalCase")]
pub struct SetOemDellBiosSerialAttrs {
    #[serde(rename = "@Redfish.SettingsApplyTime")]
    pub redfish_settings_apply_time: SetOemDellBiosSettingsApplyTime,
    pub attributes: OemDellBiosSerialAttrs,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum Tpm2HierarchySettings {
    Enabled,
    Disabled,
    Clear,
}

impl fmt::Display for Tpm2HierarchySettings {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(self, f)
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "PascalCase")]
pub struct OemDellBiosTpmAttrs {
    pub tpm_security: OnOff,
    pub tpm2_hierarchy: Tpm2HierarchySettings,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "PascalCase")]
pub struct SetOemDellBiosTpmAttrs {
    #[serde(rename = "@Redfish.SettingsApplyTime")]
    pub redfish_settings_apply_time: SetOemDellBiosSettingsApplyTime,
    pub attributes: OemDellBiosTpmAttrs
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum UefiVariableAccessSettings {
    Standard,
    Controlled,
}

impl fmt::Display for UefiVariableAccessSettings {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(self, f)
    }
}


#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "PascalCase")]
pub struct OemDellBiosLockdownAttrs {
    pub in_band_manageability_interface: EnabledDisabled,
    pub uefi_variable_access: UefiVariableAccessSettings,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "PascalCase")]
pub struct SetOemDellBiosLockdownAttrs {
    #[serde(rename = "@Redfish.SettingsApplyTime")]
    pub redfish_settings_apply_time: SetOemDellBiosSettingsApplyTime,
    pub attributes: OemDellBiosLockdownAttrs,
}

#[test]
fn test_bios_parser() {
    let test_data = include_str!("../tests/bios.json");
    let result: OemDellBios = serde_json::from_str(&test_data).unwrap();
    println!("result: {:#?}", result);
}
