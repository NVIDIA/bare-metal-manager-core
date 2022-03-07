provider "vault" {
}

resource "vault_mount" "pki" {
  path = "pki"
  type = "pki"
  description = "Dev cluster certificate issuer"
}
