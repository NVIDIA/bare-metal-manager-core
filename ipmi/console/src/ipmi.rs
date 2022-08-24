use std::net::IpAddr;

use uuid::Uuid;

use console::ConsoleError;
use rpc::forge::v0::UserRoles;

use crate::auth;

#[derive(Debug, Clone)]
pub struct IpmiInfo {
    pub ip: IpAddr,
    pub user: String,
    pub password: String,
}

#[derive(Debug, Clone)]
pub struct HostInfo {
    pub id: Uuid,
    pub ipmi_info: Option<IpmiInfo>,
}

impl IpmiInfo {
    async fn new(id: Uuid, role: UserRoles) -> Result<Self, ConsoleError> {
        IpmiInfo::get_bmc_metadata(id, role)
    }

    fn get_bmc_metadata(id: Uuid, role: UserRoles) -> Result<IpmiInfo, ConsoleError> {
        auth::get_bmc_metadata(id, role)
    }
}

impl HostInfo {
    pub async fn new(data: String, role: UserRoles) -> Result<Self, ConsoleError> {
        let uid: Uuid = Uuid::parse_str(&data).map_err(ConsoleError::from)?;
        let mut host_info = HostInfo {
            id: uid,
            ipmi_info: None,
        };

        let ipmi_info = IpmiInfo::new(host_info.id, role).await?;
        host_info.ipmi_info = Some(ipmi_info);
        Ok(host_info)
    }
}
