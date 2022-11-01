use pwhash::sha512_crypt;
use rand::distributions::Alphanumeric;
use rand::{thread_rng, Rng};
use tokio::process::Command;

use ::rpc::forge::{
    forge_client::ForgeClient, machine_credentials_update_request::CredentialPurpose,
    machine_credentials_update_request::Credentials,
};
use ::rpc::Uuid;
use cli::CarbideClientResult;

pub async fn create_users(forge_api: String, uuid: &str) -> CarbideClientResult<()> {
    let login_user_creds = create_login_user().await?;
    let hbn_user_creds = create_hbn_user().await?;
    let update_request = ::rpc::forge::MachineCredentialsUpdateRequest {
        credentials: vec![login_user_creds, hbn_user_creds],
        machine_id: Some(Uuid {
            value: uuid.to_string(),
        }),
    };

    let mut client = ForgeClient::connect(forge_api).await?;
    let request = tonic::Request::new(update_request);
    client.update_machine_credentials(request).await?;

    Ok(())
}

const RANDOM_PASSWORD_LENGTH: usize = 30;
const SSH_USERNAME: &str = "forge";
const HBN_USERNAME: &str = "cumulus";

const SSH_GROUP_NAME: &str = "forge-ssh-users";
const FORGE_USER_ID: &str = "54321";
const FORGE_GROUP_ID: &str = "54321";

async fn create_login_user() -> CarbideClientResult<Credentials> {
    let randomly_generated_ssh_password: String = thread_rng()
        .sample_iter(&Alphanumeric)
        .take(RANDOM_PASSWORD_LENGTH)
        .map(char::from)
        .collect();

    let ssh_passwd_hash = sha512_crypt::hash(randomly_generated_ssh_password.as_str())?;

    Command::new("groupadd")
        .args(["--system", "--gid", FORGE_GROUP_ID, SSH_GROUP_NAME])
        .status()
        .await?;

    Command::new("useradd")
        .args([
            "--password",
            ssh_passwd_hash.as_str(),
            "--system",
            "--no-log-init",
            "--create-home",
            "--uid",
            FORGE_USER_ID,
            "--gid",
            FORGE_GROUP_ID,
            SSH_USERNAME,
        ])
        .status()
        .await?;

    Ok(Credentials {
        user: SSH_USERNAME.to_string(),
        password: randomly_generated_ssh_password,
        credential_purpose: CredentialPurpose::LoginUser as i32,
    })
}

async fn create_hbn_user() -> CarbideClientResult<Credentials> {
    let randomly_generated_hbn_password: String = thread_rng()
        .sample_iter(&Alphanumeric)
        .take(RANDOM_PASSWORD_LENGTH)
        .map(char::from)
        .collect();

    Ok(Credentials {
        user: HBN_USERNAME.to_string(),
        password: randomly_generated_hbn_password,
        credential_purpose: CredentialPurpose::Hbn as i32,
    })
}
