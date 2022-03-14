# Maintain the state database elsewhere so that we don't maintain state between
# clearing of docker-compose data.
#
# TODO: maybe use an environment variable for this so it still works outside a
# container?
#
terraform {
  backend "local" {
    path = "/terraform/terraform.tfstate"
  }
}

provider "vault" {
}

#
# What directory do we store the generated certificates in?
#
# This is expected to be a docker volume shared among all containers that need
# a TLS certificate
#
variable "authority_output_root" {
  type = string
}

#
# All PKI operations require the PKI backend mounted
#
resource "vault_mount" "pki" {
  path = "pki"
  type = "pki"
  description = "Dev cluster certificate issuer"
}

#
# Create a backend certificate authority, EC certs only
#
resource "vault_pki_secret_backend_root_cert" "carbide" {
  depends_on = [
    vault_mount.pki
  ]

  ou = "NGC"
  organization = "NVIDIA"
  common_name = "NVIDIA Metal Development Environment"
  backend = vault_mount.pki.path
  type = "internal"
  ttl = 604800
  key_type = "ec"
  key_bits = 384
}

#
# Write the resulting CA public key to the authority_output_root which is
# shared among all the containers.
#
# The private key cannot be practicably extracted from Vault.
#
resource "local_file" "dev_certificate_authority" {
  content = vault_pki_secret_backend_root_cert.carbide.certificate
  filename = "${var.authority_output_root}/development-root-ca.pem"
}

#
# All certificate issuances require a role
#
resource "vault_pki_secret_backend_role" "service" {
  depends_on = [
    vault_pki_secret_backend_root_cert.carbide
  ]

  backend = vault_mount.pki.path
  name = "service"
  ttl = 604800
  allow_ip_sans = true
  key_type = "ec"
  key_bits = 384

  #
  # We have to allow any name here because we use the short name everywhere.
  #
  # TODO: figure out how to use `.metal.dev` as the domain name for service
  # discovery.
  #
  allow_any_name = true
  allow_subdomains = true

}

#
# Create a certificate for postgres
#
resource "vault_pki_secret_backend_cert" "postgresql" {
  backend = vault_mount.pki.path
  name = vault_pki_secret_backend_role.service.name
  common_name = "postgresql"
  ttl = 3600
  auto_renew = true
}

#
# Write out the public/private keys to the same place we wrote the CA public
# key to
#
resource "local_file" "cert_postgresql_public" {
  content = vault_pki_secret_backend_cert.postgresql.certificate
  filename = "${var.authority_output_root}/postgresql.metal.dev.pem"
}

resource "local_file" "cert_postgresql_private" {
  content = vault_pki_secret_backend_cert.postgresql.private_key
  filename = "${var.authority_output_root}/postgresql.metal.dev.key"
  file_permission = "0640"

  #
  # PostgreSQL expects the private key to be owned by postgres, which is uid 70
  # in the postgres container
  #
  provisioner "local-exec" {
    command = "chown 0:70 ${self.filename}"
  }
}
