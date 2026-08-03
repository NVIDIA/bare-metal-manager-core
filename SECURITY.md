<!--
SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
SPDX-License-Identifier: Apache-2.0
-->

# Security Policy: NVIDIA Infra Controller (NICo)

NVIDIA is dedicated to the security and trust of our software products and services, including all source code repositories managed through our organization.

## Reporting a Vulnerability

If you discover a potential security vulnerability, please **do not open a public issue or pull request.**

To report a potential security vulnerability in any NVIDIA product:

- **Web (preferred):** [NVIDIA Security Vulnerability Submission Form](https://www.nvidia.com/object/submit-security-vulnerability.html) — part of the [NVIDIA Vulnerability Disclosure Program](https://www.nvidia.com/en-us/security/)
- **E-Mail:** [psirt@nvidia.com](mailto:psirt@nvidia.com)
  - We encourage you to use the following PGP key for secure email communication: [NVIDIA public PGP Key](https://www.nvidia.com/en-us/security/pgp-key)
- **GitHub:** If private vulnerability reporting is enabled on this repository, you may also submit a report through the **Security** tab → **Report a vulnerability**. Never use public issues or pull requests for security reports.

Please include the following information:

- Product/project name and version/branch that contains the vulnerability
- Type of vulnerability (code execution, denial of service, buffer overflow, privilege escalation, etc.)
- Step-by-step instructions to reproduce the vulnerability
- Proof-of-concept or exploit code, if available
- Potential impact, including how an attacker could exploit the vulnerability

**Detailed reports help NVIDIA evaluate and address issues faster.** NVIDIA's PSIRT team will acknowledge receipt, validate severity, develop fixes, and publish security bulletins as appropriate.

While NVIDIA currently does not have a bug bounty program, we do offer acknowledgement when an externally reported security issue is addressed under our coordinated vulnerability disclosure policy. Please visit our [Product Security Incident Response Team (PSIRT)](https://www.nvidia.com/en-us/security/psirt-policies/) policies page for more information.

For all other security-related concerns, please visit NVIDIA's [Product Security portal](https://www.nvidia.com/en-us/security).

## Security Architecture & Context

NVIDIA Infra Controller (NICo) is a site-local control plane that provides zero-touch lifecycle automation for bare-metal datacenter systems: discovery, provisioning, network virtualization, credential rotation, firmware management, and decommissioning, with DPU-enforced tenant isolation.

This software operates at the **Service** level — a distributed control plane deployed as a set of Kubernetes workloads (Helm charts under `helm/` and `helm-prereqs/`), accompanied by an administrative CLI (`crates/admin-cli`) and a public REST API surface (`rest-api/`). It is a mix of Rust (~100 workspace crates under `crates/`) and Go (the REST/flow layer under `rest-api/`).

Its primary security responsibility is to **protect privileged infrastructure credentials and enforce isolation between tenants sharing physical infrastructure.** Specifically: BMC, UEFI, and switch management credentials; the integrity of the machine provisioning and boot path; and the correctness of network, InfiniBand, and NVLink partitioning that separates one tenant's compute from another's.

**Repository Exposure Classification:** Public.
Basis: origin remote is github.com and the repository is publicly readable under Apache-2.0; this document is written to public-safe detail.

**Service Exposure Classification:** External / Regulated (high confidence).
Basis: externally distributed as container images and Helm charts with public product documentation; operates as a customer-facing bare-metal control plane; handles infrastructure credentials, secrets, and multi-tenant isolation boundaries.

### Trust Boundaries and Interfaces

- **Administrative / external API.** The Go REST layer authenticates callers via OIDC tokens issued by an external identity provider (`rest-api/auth/pkg/authentication/`), with organization-scoped authorization (`rest-api/auth/pkg/authorization/org.go`) and JWKS-based token validation (`rest-api/auth/pkg/config/jwks.go`). This is the boundary between customer/operator identity and the control plane.
- **Internal control-plane RPC.** Services communicate over gRPC (`crates/rpc/proto/`) with mutual TLS. Peer identity is derived from SPIFFE IDs carried in X.509 certificates (`crates/authn/`), and access decisions are made by a Casbin policy engine (`crates/api-core/src/auth/casbin_engine.rs`) plus a static internal rule table (`crates/api-core/src/auth/internal_rbac_rules.rs`) that maps each RPC to the service principals allowed to call it.
- **Provisioning network.** The PXE service (`crates/pxe/`) serves iPXE scripts and cloud-init documents (`user-data`, `meta-data`, `vendor-data`, `network-config`) to machines as they boot, alongside a DHCP server (`crates/dhcp-server/`). This boundary is deliberately unauthenticated — machines being provisioned have no credentials yet — and relies on network segmentation.
- **Hardware management.** Redfish and IPMI traffic to baseboard management controllers is brokered through a proxy with a per-principal ACL (`crates/bmc-proxy/src/acl.rs`), with serial console access via an SSH front end (`crates/ssh-console/`) and switch management through dedicated clients (`crates/nvue-client`, `crates/libnmxc`).
- **Secrets and key material.** Credentials are stored in an external secret manager (`crates/secrets/src/forge_vault.rs`) with envelope encryption (`crates/secrets/src/key_encryption.rs`, AES-GCM) and a pluggable KMS layer including a remote transit provider (`crates/kms-provider/src/providers/`).
- **Attestation and machine identity.** Machine identity is established through measured boot records (`crates/measured-boot/`), SPDM device attestation (`crates/spdm-controller/`), and an RFC 8693 token exchange (`crates/api-core/src/machine_identity/token_exchange.rs`).
- **Persistence.** State is held in PostgreSQL, accessed through `sqlx` with migrations under `crates/api-db/migrations/`.

### Threat Model

The following scenarios represent the primary security concerns for this project, including auxiliary and support code. They are derived from analysis of this repository, ordered roughly by severity and likelihood.

1. **Machine impersonation on the provisioning network:** The PXE service resolves a caller's identity from the observed connection source IP and asks the control plane for that machine's boot instructions (`crates/pxe/src/extractors/machine.rs`). The cloud-init routes (`crates/pxe/src/routes/cloud_init.rs`) carry no authentication layer — the router applies only logging, metrics, URL normalization, and client-IP extraction (`crates/pxe/src/main.rs`). A host that can occupy or spoof a target machine's address on the provisioning segment can retrieve that machine's cloud-init payload and agent configuration. Note that the extractor deliberately ignores `X-Forwarded-For`, so an upstream proxy cannot be used to forge this identity.

2. **Compromise of privileged hardware credentials:** BMC, UEFI, and switch credentials are held in the secret store and rotated by dedicated controllers (`crates/credential-rotation/`, `crates/machine-controller/src/handler/host_uefi_rotation.rs`, `crates/machine-controller/src/handler/dpu_uefi_rotation.rs`). An attacker who obtains a service principal permitted by the BMC proxy ACL, or who reaches the secret store directly, gains Redfish and IPMI control of physical hardware — power state, boot device, firmware, and virtual media — which is effectively unbounded control over tenant workloads.

3. **Interception on the hardware-management path:** The Redfish client pool is constructed with certificate validation disabled (`crates/api-core/src/setup.rs`), and a permissive TLS verifier exists for optional-validation cases (`crates/tls/src/dummy_tls_verifier.rs`), used by fabric and telemetry clients including `crates/ib-fabric/`, `crates/nvlink-manager/`, and `crates/health/`. This is a deliberate accommodation for the self-signed certificates that BMCs and fabric appliances ship with, but it means an attacker positioned on the management network can intercept or modify those sessions, including credential material presented to devices.

4. **Authorization gaps in the control-plane RPC surface:** The control plane exposes a large gRPC surface (`crates/rpc/proto/forge.proto`), with every method gated by an entry in the internal rule table. A small number of methods are intentionally reachable without a service certificate — including version reporting, machine discovery, attestation quote submission, and JWKS retrieval — because they sit on the onboarding path before a machine has an identity. A missing or overly broad rule for a newly added method, or a defect in the anonymous-path matching logic, would expose privileged operations to unauthenticated callers.

5. **Tenant isolation failure in network virtualization:** Tenant separation is enforced through VPC and network segment management (`crates/api-core/src/handlers/vpc.rs`, `crates/vpc-prefix-controller/`), InfiniBand partitioning (`crates/ib-partition-controller/`), NVLink domain assignment (`crates/nvlink-manager/`), and DPU-side flow programming (`crates/agent/src/ovs.rs`). An error in segment, partition, or domain assignment — particularly during reprovisioning or decommissioning, when a machine transitions between tenants — could leave one tenant reachable from another's network or fabric.

6. **Firmware and artifact integrity in the update path:** The firmware downloader verifies a SHA-256 checksum when one is supplied and skips verification when the supplied checksum is empty (`crates/firmware/src/downloader.rs`); the implementation notes that this check is intended to detect corruption rather than to serve as a security control. Combined with the component manager's update flows, a compromised artifact source or tampered catalogue metadata could result in attacker-chosen firmware being staged onto managed hardware.

7. **Credential leakage through telemetry, logging, and diagnostics:** Tracing and metrics instrumentation is pervasive (`crates/instrument/`, `crates/instrument-macros/`), SSH console sessions are recorded (`crates/ssh-console/src/console_logger.rs`), and diagnostic tooling explores BMC endpoints and captures responses (`crates/bmc-explorer/`, `crates/api-core/src/handlers/bmc_endpoint_explorer.rs`). These paths run adjacent to credential handling, so an over-broad span field, error message, or captured response body could persist secrets into logs, traces, or metrics backends that have a wider audience than the control plane itself.

### Critical Security Assumptions

The following are conditions this software assumes are already satisfied by another layer. They are stated explicitly because the code does not enforce them.

- **The provisioning network is a trusted, segmented L2 domain.** PXE, DHCP, and cloud-init delivery authenticate nothing; machine identity on that path is network position. Isolation of the provisioning VLAN from tenant and corporate networks is the operator's responsibility.
- **The hardware management network is isolated.** Certificate validation toward BMCs and fabric appliances is intentionally relaxed to accommodate device-shipped self-signed certificates, so confidentiality and integrity on that path depend on the management network being physically or logically separated.
- **External user identity is managed elsewhere.** The REST layer validates OIDC tokens and JWKS but does not own user lifecycle, password policy, MFA, or session revocation; it assumes the configured identity provider enforces these.
- **The external secret manager and KMS are available and trustworthy.** NICo delegates secret storage, envelope key custody, and transit encryption to them, and assumes their access policies are correctly scoped.
- **The Kubernetes substrate enforces workload isolation.** Pod-level isolation, cluster RBAC, secret mounting, and network policy are assumed to work correctly; the control plane does not independently defend against a compromised co-tenant pod.
- **Firmware artifacts originate from a trusted catalogue.** Checksums confirm that a download matches what the catalogue advertised, not that the catalogue itself is authentic; supply-chain trust is assumed upstream.
- **Hardware roots of trust behave correctly.** Measured-boot and SPDM decisions trust the values reported by the TPM and device firmware; NICo does not detect a compromised root of trust.
- **Administrative CLI callers are already authenticated operators.** `crates/admin-cli` is an administrative interface that acts with the privileges of its service certificate; it is not itself a security boundary.
- **Callers supply well-formed identifiers.** Handlers validate structure and referential integrity, but the control plane assumes upstream API authentication has already established who the caller is before authorization rules are applied.

## Deployment Assumptions

- NICo is deployed into a Kubernetes cluster the operator controls, with the Helm values under `helm-prereqs/values/` adapted to site-specific network pools, VLAN ranges, and VIP assignments.
- Service-to-service mTLS requires a functioning certificate authority and rotation path (`crates/certs/src/cert_renewal.rs`); expired or unrotated certificates fail closed.
- PostgreSQL, the secret manager, and the identity provider are operated as trusted site services with their own access controls and backup policy.

## Scope and Out of Scope

**In scope:** the Rust control-plane crates under `crates/`, the Go REST and flow services under `rest-api/`, the DPU-side agent and containers under `bluefield/`, the Helm charts under `helm/`, and the deployment automation under `helm-prereqs/`.

**Out of scope:** vulnerabilities in third-party dependencies should be reported to their upstream maintainers (see `THIRD-PARTY-LICENSES` and `deny.toml`); defects in BMC, switch, or DPU firmware belong to the respective hardware product's disclosure process; and site-specific misconfiguration of the deployment values is an operational concern rather than a product vulnerability.

## Dependency Security

Dependencies are pinned through `Cargo.lock` and Go module files, with license and advisory policy enforced by `deny.toml` in CI. The cryptographic stack is `rustls` with `aws-lc-rs`, plus `aes-gcm`, `sha2`, `jsonwebtoken`, `x509-parser`, and `rcgen`; the project does not implement its own primitives.

## Common False-Positive Patterns

Automated scanning of this repository regularly surfaces the following, which are test and mock infrastructure rather than production exposure:

- `crates/bmc-mock/` — a mock BMC used in integration tests, including deliberately permissive TLS handling.
- `crates/api-core/src/auth/test_certs.rs`, `crates/secrets/src/test_support/`, `crates/test-support/`, `crates/test-harness/`, `crates/sqlx-testing/` — fixture certificates, placeholder credentials, and test doubles.
- `DummyTlsVerifier::new_for_tests()` in `crates/tls/src/dummy_tls_verifier.rs` — the test-only constructor; the production constructor emits a warning when validation is skipped.
- Placeholder values in documentation under `docs/` and `book/`, and in example Helm values.

Confirmed triage decisions for this repository are recorded in `.security-triage.yaml` at the repository root.
