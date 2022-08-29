use std::convert::TryFrom;

use sqlx::postgres::PgRow;
use sqlx::{Postgres, Row};

use rpc::forge::v0 as rpc;

use crate::{db::ipmi::UserRoles, CarbideError, CarbideResult};

#[derive(Clone, Debug)]
pub struct SshKeyValidationRequest {
    pub user: String,
    pub pubkey: String,
}

struct SshPublicKeys {
    role: UserRoles,
    pubkeys: Vec<String>,
}

impl TryFrom<rpc::SshKeyValidationRequest> for SshKeyValidationRequest {
    type Error = CarbideError;

    fn try_from(value: rpc::SshKeyValidationRequest) -> Result<Self, Self::Error> {
        Ok(SshKeyValidationRequest {
            user: value.user,
            pubkey: value.pubkey,
        })
    }
}

impl<'r> sqlx::FromRow<'r, PgRow> for SshPublicKeys {
    fn from_row(row: &'r PgRow) -> Result<Self, sqlx::Error> {
        Ok(SshPublicKeys {
            role: row.try_get("role")?,
            pubkeys: row.try_get("pubkeys")?,
        })
    }
}

impl SshKeyValidationRequest {
    pub async fn verify_user(
        &self,
        txn: &mut sqlx::Transaction<'_, Postgres>,
    ) -> CarbideResult<rpc::SshKeyValidationResponse> {
        let user_info: SshPublicKeys =
            sqlx::query_as("SELECT role, pubkeys from ssh_public_keys WHERE username=$1")
                .bind(&self.user)
                .fetch_one(&mut *txn)
                .await
                .map_err(CarbideError::from)?;

        for pkey in user_info.pubkeys {
            let key = pkey.lines().collect::<Vec<&str>>().join("");
            if key.contains(&self.pubkey) {
                // Key matched
                return Ok(rpc::SshKeyValidationResponse {
                    is_authenticated: true,
                    role: rpc::UserRoles::from(user_info.role) as i32,
                });
            }
        }

        Ok(rpc::SshKeyValidationResponse {
            is_authenticated: false,
            role: rpc::UserRoles::Noaccess as i32,
        })
    }
}
