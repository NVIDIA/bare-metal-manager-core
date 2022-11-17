use std::fmt;
use std::fmt::Formatter;
use crate::common::*;

#[derive(Debug)]
pub enum SystemPowerControl {
    On,
    ForceOff,
    ForceRestart,
    GracefulRestart,
    GracefulShutdown,
    PushPowerButton,
    PowerCycle,
}

impl fmt::Display for SystemPowerControl {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(self, f)
    }
}

#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "PascalCase")]
pub struct StatusState {
    pub state: String,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "PascalCase")]
pub struct OemDellSystem {
    #[serde(rename = "BIOSReleaseDate")]
    pub bios_release_date: String,
    pub chassis_service_tag: String,
    pub chassis_system_height_unit: i64,
    pub estimated_exhaust_temperature_celsius: i64,
    #[serde(rename = "EstimatedSystemAirflowCFM")]
    pub estimated_system_airflow_cfm: i64,
    pub express_service_code: String,
    pub fan_rollup_status: String,
    pub intrusion_rollup_status: String,
    pub managed_system_size: String,
    #[serde(rename = "MaxCPUSockets")]
    pub max_cpu_sockets: i64,
    #[serde(rename = "MaxDIMMSlots")]
    pub max_dimm_slots: i64,
    #[serde(rename = "MaxPCIeSlots")]
    pub max_pcie_slots: i64,
    #[serde(rename = "PopulatedDIMMSlots")]
    pub populated_dimm_slots: i64,
    #[serde(rename = "PopulatedPCIeSlots")]
    pub populated_pcie_slots: i64,
    pub power_cap_enabled_state: String,
    pub system_generation: String,
    pub temp_rollup_status: String,
    #[serde(rename = "UUID")]
    pub uuid: String,
    pub volt_rollup_status: String,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "PascalCase")]
pub struct OemDell {
    pub dell_system: OemDellSystem,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "PascalCase")]
pub struct OemData {
    pub dell: OemDell,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "PascalCase")]
pub struct SystemStatus {
    pub health: String,
    pub health_rollup: String,
    pub state: String,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "PascalCase")]
pub struct SystemProcessors {
    pub count: i64,
    pub logical_processor_count: i64,
    pub model: String,
    pub status: SystemStatus,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "PascalCase")]
pub struct TrustedModule {
    pub firmware_version: String,
    pub interface_type: String,
    pub status: StatusState,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "PascalCase")]
pub struct ComputerSystem {
    pub asset_tag: String,
    pub bios_version: String,
    pub manufacturer: String,
    pub model: String,
    pub oem: OemData,
    pub part_number: String,
    pub power_state: String,
    pub processor_summary: SystemProcessors,
    #[serde(rename = "SKU")]
    pub sku: String,
    pub serial_number: String,
    pub status: SystemStatus,
    pub trusted_modules: Vec<TrustedModule>
}

#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "PascalCase")]
pub struct Systems {
    #[serde(rename = "@odata.context")]
    pub odata_context: String,
    pub members: Vec<ODataId>,
    pub name: String,
}

#[test]
fn test_system_parser() {
    let test_data1 = include_str!("../tests/systems.json");
    let result1: Systems = serde_json::from_str(&test_data1).unwrap();
    let test_data2 = include_str!("../tests/system.json");
    let result2: ComputerSystem = serde_json::from_str(&test_data2).unwrap();
    println!("result1: {:#?}", result1);
    println!("result2: {:#?}", result2);
}
