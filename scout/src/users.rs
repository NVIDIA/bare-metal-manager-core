use std::path::Path;

use ::rpc::forge::{
    forge_client::ForgeClient, machine_credentials_update_request::CredentialPurpose,
    machine_credentials_update_request::Credentials,
};
use pwhash::sha512_crypt;
use rand::distributions::Alphanumeric;
use rand::{thread_rng, Rng};
use tokio::fs::File;
use tokio::io::AsyncWriteExt;
use tokio::process::Command;

use crate::{CarbideClientError, CarbideClientResult};

pub async fn create_users(forge_api: String, machine_id: &str) -> CarbideClientResult<()> {
    let login_user_creds = create_login_user().await?;
    let hbn_user_creds = create_hbn_user().await?;
    let update_request = ::rpc::forge::MachineCredentialsUpdateRequest {
        credentials: vec![login_user_creds, hbn_user_creds],
        machine_id: Some(machine_id.to_string().into()),
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

    let mut command = Command::new("groupadd");
    command.args(["--system", "--gid", FORGE_GROUP_ID, SSH_GROUP_NAME]);
    let output = command.output().await?;
    if !output.status.success() {
        return Err(CarbideClientError::subprocess_error(
            command.as_std(),
            &output,
        ));
    }

    let mut command = Command::new("useradd");
    let output = command
        .args([
            "--password",
            ssh_passwd_hash.as_str(),
            "--system",
            "--no-log-init",
            "--create-home",
            "--shell",
            "/bin/bash",
            "--uid",
            FORGE_USER_ID,
            "--gid",
            FORGE_GROUP_ID,
            "--groups",
            "adm,dialout,cdrom,floppy,sudo,audio,dip,video,plugdev,netdev,lxd",
            SSH_USERNAME,
        ])
        .output()
        .await?;
    if !output.status.success() {
        return Err(CarbideClientError::subprocess_error(
            command.as_std(),
            &output,
        ));
    }

    //this is not a typo, the directory is *called* sudoers.d
    let sudoers_dot_d = Path::new("/etc/sudoers.d");
    if sudoers_dot_d.exists() {
        // QEMU hosts don't have sudo at all
        let mut sudo_include_file =
            File::create(sudoers_dot_d.join("99_sudo_include_file")).await?;
        let sudoers_line = format!("{} ALL=(ALL) NOPASSWD:ALL\n", SSH_USERNAME);
        sudo_include_file.write_all(sudoers_line.as_bytes()).await?;
        sudo_include_file.flush().await?;
    }

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
