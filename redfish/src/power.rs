use crate::common::*;

#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "PascalCase")]
pub struct OemHpSnmppowerthresholdalert {
    pub duration_in_min: i64,
    pub threshold_watts: i64,
    pub trigger: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct OemHp {
    #[serde(flatten)]
    pub oem_type: HpType,
    #[serde(rename = "SNMPPowerThresholdAlert")]
    pub snmp_power_threshold_alert: OemHpSnmppowerthresholdalert,
    #[serde(flatten)]
    pub links: LinkType,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "PascalCase")]
pub struct Oem {
    pub hp: OemHp,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "PascalCase")]
pub struct PowercontrolPowerlimit {
    pub limit_in_watts: Option<i64>,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "PascalCase")]
pub struct PowercontrolPowermetric {
    pub average_consumed_watts: i64,
    pub interval_in_min: i64,
    pub max_consumed_watts: i64,
    pub min_consumed_watts: i64,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "PascalCase")]
pub struct Powercontrol {
    pub power_capacity_watts: i64,
    pub power_consumed_watts: i64,
    pub power_limit: PowercontrolPowerlimit,
    pub power_metrics: PowercontrolPowermetric,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "PascalCase")]
pub struct PowersuppliesOemHpPowersupplystatus {
    pub state: String,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "PascalCase")]
pub struct PowersuppliesOemHp {
    #[serde(flatten)]
    pub power_type: HpType,
    pub average_power_output_watts: i64,
    pub bay_number: i64,
    pub hotplug_capable: bool,
    pub max_power_output_watts: i64,
    pub mismatched: bool,
    pub power_supply_status: PowersuppliesOemHpPowersupplystatus,
    #[serde(rename = "iPDUCapable")]
    pub i_pdu_capable: bool,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "PascalCase")]
pub struct PowersuppliesOem {
    pub hp: PowersuppliesOemHp,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "PascalCase")]
pub struct Powersupply {
    pub firmware_version: String,
    pub last_power_output_watts: i64,
    pub line_input_voltage: i64,
    pub line_input_voltage_type: String,
    pub model: String,
    pub name: String,
    pub oem: PowersuppliesOem,
    pub power_capacity_watts: i64,
    pub power_supply_type: String,
    pub serial_number: String,
    pub spare_part_number: String,

    pub status: AllStatus,
}

impl Status for Powersupply {
    fn health(&self) -> String {
        self.status.health()
    }

    fn state(&self) -> String {
        self.status.state()
    }
}

#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "PascalCase")]
pub struct Redundancy {
    pub max_num_supported: i64,
    pub member_id: String,
    pub min_num_needed: i64,
    pub mode: String,
    pub name: String,
    pub redundancy_set: Vec<ODataId>,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "PascalCase")]
pub struct Power {
    #[serde(flatten)]
    pub odata: ODataLinks,
    pub id: String,
    pub name: String,
    pub oem: Oem,
    pub power_capacity_watts: i64,
    pub power_consumed_watts: i64,
    pub power_control: Vec<Powercontrol>,
    pub power_limit: PowercontrolPowerlimit,
    pub power_metrics: PowercontrolPowermetric,
    pub power_supplies: Vec<Powersupply>,
    pub redundancy: Vec<Redundancy>,
    #[serde(rename = "Type")]
    pub power_type: String,
}

impl StatusVec for Power {
    fn get_vec(&self) -> Vec<Box<dyn Status>> {
        let mut v: Vec<Box<dyn Status>> = Vec::new();
        for res in &self.power_supplies {
            v.push(Box::new(res.clone()))
        }
        v
    }
}

#[test]
fn test_power_parser() {
    let test_data = include_str!("../tests/power.json");
    let result: Power = serde_json::from_str(&test_data).unwrap();
    println!("result: {:#?}", result);
}
