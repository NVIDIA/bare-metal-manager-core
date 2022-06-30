use carbide::db::ipmi::IpmiIp;
use sqlx::{self, PgPool};
use std::io::{Error, ErrorKind};
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct IpmiInfo {
    pub ip: String,
    pub user: Option<String>,
    pub password: Option<String>,
}

#[derive(Debug, Clone)]
pub struct HostInfo {
    pub id: Uuid,
    pub ipmi_info: Option<IpmiInfo>,
}

impl IpmiInfo {
    async fn new(id: Uuid, pool: PgPool) -> Result<Self, sqlx::Error> {
        Ok(IpmiInfo {
            ip: IpmiIp::new(id, pool).await?.ip,
            user: None,
            password: None,
        })
    }

    #[cfg(not(test))]
    fn get_ipmi_credentials(id: Uuid) -> Result<(String, String), sqlx::Error> {
        panic!("Not implemented: id: {}.", id);
    }

    #[cfg(test)]
    fn get_ipmi_credentials(_id: Uuid) -> Result<(String, String), sqlx::Error> {
        Ok(("user".to_string(), "password".to_string()))
    }
}

impl HostInfo {
    pub async fn new(data: String, pool: PgPool) -> Result<Self, sqlx::Error> {
        let uid: Uuid = Uuid::parse_str(&data).map_err(|x| {
            sqlx::Error::Io(Error::new(
                ErrorKind::Other,
                format!("Not a valid machine id. Parsing uuid failed. Error: {}", x),
            ))
        })?;
        let mut host_info = HostInfo {
            id: uid,
            ipmi_info: None,
        };

        let mut ipmi_info = IpmiInfo::new(host_info.id, pool).await?;
        let (user, password) = IpmiInfo::get_ipmi_credentials(host_info.id)?;
        ipmi_info.user = Some(user);
        ipmi_info.password = Some(password);
        host_info.ipmi_info = Some(ipmi_info);
        Ok(host_info)
    }
}
