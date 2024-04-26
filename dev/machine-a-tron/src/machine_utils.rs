use mac_address::MacAddress;

use crate::{api_client, config::MachineATronContext};

use std::sync::atomic::{AtomicU32, Ordering};
/*
#[derive(Clone)]
pub struct MacAddr {
    mac_addr: [u8; 6],
}

impl MacAddr {
    pub fn as_slice(&self) -> &[u8] {
    }
}

impl FromIterator<u8> for MacAddr {
    fn from_iter<T: IntoIterator<Item = u8>>(iter: T) -> Self {

        MacAddr { mac_addr:  <[u8;6]>::try_from(iter.into_iter()).expect("Failed to parse u8 slice")}
    }
}

impl ToString for MacAddr {
    fn to_string(&self) -> String {
        format!(
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            self.mac_addr[0],
            self.mac_addr[1],
            self.mac_addr[2],
            self.mac_addr[3],
            self.mac_addr[4],
            self.mac_addr[5],
        )
    }
}

impl Debug for MacAddr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_string())
    }
}

impl FromStr for MacAddr {
    type Err = ParseIntError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        (0..s.len())
        .step_by(3)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16))
        .collect()
    }
}

#[test]
fn mac_addr_to_string() {
    let expected =
}
*/

static NEXT_MAC_ADDRESS: AtomicU32 = AtomicU32::new(1);

pub fn next_mac() -> MacAddress {
    let next_mac_num = NEXT_MAC_ADDRESS.fetch_add(1, Ordering::Acquire);

    let bytes: Vec<u8> = [0x02u8, 0x01]
        .into_iter()
        .chain(next_mac_num.to_be_bytes())
        .collect();

    let mac_bytes = <[u8; 6]>::try_from(bytes).unwrap();

    MacAddress::from(mac_bytes)
}

pub async fn get_fac_action(
    app_context: &MachineATronContext,
    machine_id: rpc::forge::MachineId,
) -> rpc::forge::forge_agent_control_response::Action {
    let response = api_client::forge_agent_control(app_context, machine_id.clone())
        .await
        .unwrap();
    let action =
        rpc::forge::forge_agent_control_response::Action::try_from(response.action).unwrap();

    tracing::info!("{}: control action: {}", machine_id, action.as_str_name());

    action
}

pub async fn reboot_requested(
    app_context: &MachineATronContext,
    machine_id: &rpc::forge::MachineId,
) -> bool {
    let machine = api_client::get_machine(app_context, machine_id.clone())
        .await
        .unwrap();

    let mut reboot_requested = false;

    if let Some(m) = machine {
        if let Some(last_reboot_requested_time) = m.last_reboot_requested_time {
            if let Some(last_reboot_time) = m.last_reboot_time {
                let last_reboot_requested_time =
                    chrono::DateTime::try_from(last_reboot_requested_time).unwrap();
                let last_reboot_time = chrono::DateTime::try_from(last_reboot_time).unwrap();

                reboot_requested = last_reboot_requested_time > last_reboot_time;
            }
        }
    }
    if reboot_requested {
        tracing::info!("reboot requested for {}", machine_id,);
    }
    reboot_requested
}

pub async fn get_api_state(
    app_context: &MachineATronContext,
    machine_id: &rpc::forge::MachineId,
) -> String {
    let machine = api_client::get_machine(app_context, machine_id.clone())
        .await
        .unwrap();

    if let Some(m) = machine {
        m.state
    } else {
        "".to_owned()
    }
}
