use crate::common::*;

#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "PascalCase")]
pub struct FansOemHp {
    #[serde(flatten)]
    pub fan_type: HpType,
    pub location: String,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "PascalCase")]
pub struct FansOem {
    pub hp: FansOemHp,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "PascalCase")]
pub struct Fan {
    pub current_reading: i64,
    pub fan_name: String,
    pub oem: FansOem,
    pub status: SomeStatus,
    pub units: String,
}
impl Status for Fan {
    fn health(&self) -> String {
        self.status.health()
    }

    fn state(&self) -> String {
        self.status.state()
    }
}

#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "PascalCase")]
pub struct TemperaturesOemHp {
    #[serde(flatten)]
    pub temp_type: HpType,
    pub location_xmm: i64,
    pub location_ymm: i64,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "PascalCase")]
pub struct TemperaturesOem {
    pub hp: TemperaturesOemHp,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "PascalCase")]
pub struct Temperature {
    pub current_reading: i64,
    pub name: String,
    pub number: i64,
    pub lower_threshold_critical: Option<i64>,
    pub lower_threshold_fatal: Option<i64>,
    pub oem: TemperaturesOem,
    pub physical_context: String,
    pub reading_celsius: i64,
    pub status: SomeStatus,
    pub units: String,
    pub upper_threshold_critical: i64,
    pub upper_threshold_fatal: i64,
}
impl Status for Temperature {
    fn health(&self) -> String {
        self.status.health()
    }

    fn state(&self) -> String {
        self.status.state()
    }
}

#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "PascalCase")]
pub struct Thermal {
    #[serde(flatten)]
    pub odata: ODataLinks,
    pub fans: Vec<Fan>,
    pub id: String,
    pub name: String,
    pub temperatures: Vec<Temperature>,
    #[serde(rename = "Type")]
    pub thermal_type: String,
}

impl StatusVec for Thermal {
    fn get_vec(&self) -> Vec<Box<dyn Status>> {
        let mut v: Vec<Box<dyn Status>> = Vec::new();
        for res in &self.fans {
            v.push(Box::new(res.clone()))
        }
        for res in &self.temperatures {
            v.push(Box::new(res.clone()))
        }
        v
    }
}

#[test]
fn test_thermal_parser() {
    let test_data = include_str!("../tests/chassis-thermal.json");
    let result: Thermal = serde_json::from_str(&test_data).unwrap();
    println!("result: {:#?}", result);
}
