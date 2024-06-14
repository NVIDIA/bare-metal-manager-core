import os
from typing import Literal

import hvac

VAULT_ADDR = os.environ.get("VAULT_ADDR", "https://prod.vault.nvidia.com")
VAULT_NAMESPACE = os.environ.get("VAULT_NAMESPACE", "ngc-forge")


class VaultError(Exception):
    """Exception for Vault related errors."""


class ForgeVaultClient:
    """Class for getting what we need from Vault.

    This is a context manager - use it in a with block to ensure the client
    is closed at the end.
    """

    def __init__(self, path: str, mount_point: str = "secrets"):
        self.path = path
        self.mount_point = mount_point
        self.client = None

    def __enter__(self):
        self.client = vault_login()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.client.logout()

    def get_dpu_bmc_credentials(self):
        read_response = self.client.secrets.kv.v2.read_secret(mount_point=self.mount_point, path=self.path)
        dpu_bmc_creds = read_response["data"]["data"]["dpu_bmc_creds"]
        dpu_bmc_username, dpu_bmc_password = dpu_bmc_creds.split(":", maxsplit=1)
        return dpu_bmc_username, dpu_bmc_password

    def get_host_bmc_credentials(self):
        read_response = self.client.secrets.kv.v2.read_secret(mount_point=self.mount_point, path=self.path)
        host_bmc_creds = read_response["data"]["data"]["idrac_creds"]
        host_bmc_username, host_bmc_password = host_bmc_creds.split(":", maxsplit=1)
        return host_bmc_username, host_bmc_password

    def get_ngc_api_key(self, environment: Literal["prod", "stg"]):
        read_response = self.client.secrets.kv.v2.read_secret(mount_point=self.mount_point, path=self.path)
        if environment == "prod":
            return read_response["data"]["data"]["nvcr"]
        elif environment == "stg":
            return read_response["data"]["data"]["stg_nvcr"]
        else:
            raise ValueError(f"Unknown environment: {environment}")

    def get_ssh_private_key(self):
        read_response = self.client.secrets.kv.v2.read_secret(mount_point=self.mount_point, path=self.path)
        ssh_private_key = read_response["data"]["data"]["ssh_private_key"]
        return ssh_private_key


def vault_login() -> hvac.Client:
    """Authenticate to Vault & return a client object.

    Works for GitLab CI and local dev environment where a token exists at ${HOME}/.vault-token
    Don't forget to call logout() on the client with finished with it.
    """
    if "VAULT_JWT_TOKEN" in os.environ:
        # GitLab CI
        client = hvac.Client(
            url=VAULT_ADDR,
            namespace=VAULT_NAMESPACE,
        )
        client.auth.jwt.jwt_login(
            role=os.environ["VAULT_JWT_ROLE"],
            path="/".join(os.environ["VAULT_JWT_PATH"].split("/")[1:-1]),
            jwt=os.environ["VAULT_JWT_TOKEN"],
        )
    else:
        # Running on dev machine
        with open(f"{os.environ['HOME']}/.vault-token") as token_file:
            client = hvac.Client(
                url=VAULT_ADDR,
                namespace=VAULT_NAMESPACE,
                token=token_file.read(),
            )
    if client.is_authenticated():
        return client
    else:
        raise VaultError("Failed to authenticate to Vault")
