# Vault-Free NICo Runtime

## High-Level Design

## Revision History

| Version | Date | Modified By | Description |
| :---: | :---: | :--- | :--- |
| 0.1 | 2026-08-27 | Bill Minckler | Initial high-level design across the three Vault-elimination epics |
| 0.2 | 2026-08-28 | Bill Minckler | Reconcile the design with the current epic subtasks and implementation |
| 0.3 | 2026-08-28 | Bill Minckler | Separate the completed target design from implementation status and cross-epic intermediate states |
| 0.4 | 2026-09-02 | Bill Minckler | Add the Vault touchpoint inventory and Vault-free installation; keep mTLS for backward compatibility; make fTPM certificate provisioning an open question; defer KEK mechanics to the operator page; refresh status |

## 1. Purpose and Scope

This document defines the target architecture for running NICo without
Vault/OpenBao. It covers the three related epics:

- [Phase 1: credential storage](https://github.com/NVIDIA/infra-controller/issues/195)
- [Phase 2: node API authentication](https://github.com/NVIDIA/infra-controller/issues/5199)
- [Phase 3: remaining key and certificate services](https://github.com/NVIDIA/infra-controller/issues/5200)

The design is intentionally high level. The following subsystem designs remain
authoritative for their implementation:

- [PostgreSQL-backed secret storage](postgres-secrets/README.md)
- [Secrets-storage operator contract](../configuration/secrets-storage.md)
- [Node-auth bearer JWTs](machine-identity/node-auth-jwt.md)
- [Machine-identity JWT-SVIDs and signing-key storage](machine-identity/spiffe-svid-sdd.md)
- [Certificate-provider separation implementation](https://github.com/NVIDIA/infra-controller/pull/2881)

The three phases are tracking boundaries, not a requirement to implement each
part serially. Work can proceed in parallel where the dependencies in
[Section 4](#4-migration-and-dependency-order) permit it.

### 1.1 Goals

- Make Vault/OpenBao optional during migration and absent from the supported
  steady-state installation, runtime, and recovery path.
- Preserve credential confidentiality, machine identity, and existing RBAC
  semantics.
- Migrate live sites incrementally, with explicit overlap and rollback paths.
- Keep storage, key custody, node authentication, and certificate issuance as
  separate provider boundaries.
- Fail clearly when a required non-Vault provider or node credential is
  unavailable.

### 1.2 Non-Goals

- Repeating the low-level designs linked above.
- Removing TLS or certificates from every NICo service. Phase 2 removes machine
  mTLS as the required Scout and DPU-agent API credential; transport TLS and
  other certificate consumers remain. The admin CLI uses no Vault-issued
  credential, and the selected Vault-free authentication method may retain mTLS.
- Removing mTLS on a fixed date. Machine mTLS remains supported for backward
  compatibility for as long as a deployment needs it; each site disables it
  after the criteria in [Section 3.2](#32-phase-2-node-api-authentication) are
  met.
- Using the BlueField IRoT key as the node-JWT signing credential. The DPU OS
  cannot use that key to prove possession, so the target uses a signing key that
  is accessible to the node software and protected by a hardware-backed holder.
- Defining full measured-boot or runtime attestation for DPUs.

## 2. End-State Design Summary

| Phase | Completed state |
| :--- | :--- |
| 1 — credentials | NICo-managed credentials are envelope-encrypted in PostgreSQL; operator-provided credentials come from file, environment, or mounted-secret sources; no credential consumer constructs or depends directly on a Vault client |
| 2 — authentication | Scout and DPU-agent sign short-lived bearer JWTs with hardware-backed keys and certificates rooted outside Vault; the API preserves the existing machine principal and RBAC policy; machine mTLS remains available for backward compatibility for as long as a deployment needs it; the admin CLI uses no Vault-issued credential |
| 3 — keys and certificates | An approved non-Vault provider owns the PostgreSQL KEKs; machine-identity signing-key encryption uses the shared KMS-backed envelope; every required certificate is issued and validated through a non-Vault provider; a site is installed and operated without deploying Vault |

### 2.1 Vault Touchpoints

The table is the inventory that the three epics replace. The phase column names
the epic that owns the replacement.

| Component | Vault use | End state | Phase |
| :--- | :--- | :--- | :---: |
| `nico-api` NICo-managed credentials: BMC, UEFI, and switch passwords; rack-maintenance access tokens | KV v2 store behind the credential chain | Envelope-encrypted PostgreSQL journal | 1 |
| `nico-api` operator-provided credentials: UFM, NMX-M, factory defaults | KV v2 store | Environment, file, or mounted-secret sources, with live reload where an integration requires rotation without restart | 1 |
| `nico-api` PostgreSQL KEKs | Transit wrap and unwrap when KEK custody is in Vault | Qualified non-Vault KMS provider | 3 |
| `nico-api` machine-identity signing-key encryption | Master key read through the credential chain, which may be Vault-backed | Shared KMS-backed envelope on the same non-Vault provider | 3 |
| Node certificates issued at discovery, attestation, and renewal (`DiscoverMachine`, `AttestQuote`, `RenewMachineCertificate`) | Vault PKI through `CertificateProvider` | Non-Vault certificate provider; API authentication uses node JWTs | 2, 3 |
| UFM TLS certificates issued through `SetCredential` | Vault PKI through `CertificateProvider` | Non-Vault certificate provider | 3 |
| Service transport TLS for `nico-api`, `bmc-proxy`, `dsx-exchange-consumer`, `flow`, `pxe`, `dns`, `hardware-health`, `machine-a-tron` | cert-manager `ClusterIssuer` `vault-nico-issuer`, signed by Vault PKI | cert-manager with a non-Vault issuer; trust bundle rolled over as in [Section 3.3](#33-phase-3-kek-custody-and-certificate-issuance) | 3 |
| Admin CLI client certificates | Vault PKI role `nico-cli-client`, issued by an operator | Operator-managed non-Vault PKI or a replacement credential ([Section 7](#7-open-questions)) | 2 |
| `dsx-exchange-consumer` credentials | Default credential chain, which always constructs a Vault client | Environment, file, or mounted-secret source; the default chain constructs its Vault reader only when configured | 3 |
| `bmc-proxy` and `machine-a-tron` chart mounts | Vault AppRole and token Secrets mounted by the charts; neither binary constructs a Vault client | Mounts removed | 3 |
| `nico-flow` PSM and NSM containers | Vault tokens for dynamic secrets | Scope decision in [Section 7](#7-open-questions) | 3 |
| REST API services: `cert-manager`, `site-manager`, `powershelf-manager` | Vault root CA key through Vault Agent; TLS certificates from that CA; a Vault credential datastore | Scope decision in [Section 7](#7-open-questions) | 3 |
| Deployment tooling: `helm-prereqs` and chart defaults | Installs and unseals Vault; creates PKI roles, policies, and token jobs; charts default to the Vault issuer, Secrets, and `vault-cluster-info` ConfigMap | Vault-optional installation and defaults | 3 |

## 3. Target Architecture

```mermaid
flowchart LR
    Inputs[Operator-provided files, environment, or mounted secrets]
    Generated[NICo-generated credentials]
    Chain[Credential reader and writer chain]
    Postgres[(Envelope-encrypted PostgreSQL secrets)]
    KMS[Approved non-Vault KEK provider]

    Node[Scout or DPU-agent]
    TPM[fTPM-backed signing key]
    NodeCert[Node certificate for the fTPM key]
    JWT[Short-lived node JWT with certificate chain]
    AdminCLI[Admin CLI]
    AdminAuth[Selected Vault-free CLI credential]
    API[NICo API authentication and existing RBAC]

    CertConsumers[Remaining certificate consumers]
    CertProvider[CertificateProvider]
    CA[Non-Vault CA or API trust anchor]

    Vault[Vault or OpenBao during migration only]

    Inputs --> Chain
    Generated --> Chain
    Chain --> Postgres
    Chain -->|Wrap and unwrap DEKs| KMS
    Vault -. read, import, and key overlap .-> Chain
    Vault -. KEK unwrap overlap .-> KMS

    Node --> TPM
    TPM --> JWT
    CA -->|Issues| NodeCert
    CA -->|Trust bundle| API
    NodeCert --> JWT
    JWT --> API
    AdminCLI --> AdminAuth
    AdminAuth --> API

    CertConsumers --> CertProvider
    CertProvider --> CA
    Vault -. certificate overlap .-> CertProvider
```

The end state has four independent security boundaries:

1. PostgreSQL stores encrypted credential records; an approved non-Vault KEK
   provider owns the KEKs.
2. Nodes sign their own short-lived authentication tokens with hardware-backed
   keys. The API maps the verified certificate identity to the same machine
   principal used by the current RBAC policy.
3. Certificate consumers use a provider backed by a non-Vault CA. Node
   authentication no longer requires a Vault-issued mTLS certificate, but the
   node JWT design still requires a certificate corresponding to its signing
   key and chaining to a trust anchor that remains after Vault PKI is retired.
4. The admin CLI uses the selected Vault-free credential: either mTLS backed by
   an operator-managed non-Vault PKI or a replacement authentication method.

### 3.1 Phase 1: Credential Storage

Every credential consumer uses the credential-provider abstraction rather than
constructing or depending directly on a Vault client. NICo-managed credentials
are written to the envelope-encrypted PostgreSQL journal. Operator-provided
credentials are read from explicitly configured environment, file, or mounted
secret sources, including live reload where an integration requires rotation
without restarting NICo. Services outside `nico-api` that read credentials use
the same abstraction, and the default chain constructs its Vault reader only
when configured.

The reader chain makes source ownership and precedence explicit. A locally
authoritative integration never falls through to a persistent backend and
rejects persistent mutations, while a migration configuration may prefer local
data and fall through to PostgreSQL. All other writes use the configured
persistent writer. The UFM integration implements this contract
([#1837](https://github.com/NVIDIA/infra-controller/issues/1837)); an operator
page for its local sources is a documentation follow-up recorded in
[Section 8](#8-implementation-status).

The [PostgreSQL secret-storage design](postgres-secrets/README.md) remains
authoritative for the credential chain, envelope encryption, Vault import, KEK
routing, re-wrap, and rollback behavior. [Secrets Storage](../configuration/secrets-storage.md)
defines the operator-facing persistent-store contract.

### 3.2 Phase 2: Node API Authentication

Scout and DPU-agent authenticate to the API with the bearer-JWT model defined by
[Node-auth bearer JWTs](machine-identity/node-auth-jwt.md). The token format,
short lifetime, API validation, machine-principal mapping, and RBAC behavior are
unchanged. Nodes re-mint tokens locally as expiration approaches; there is no
server-side token issuance or refresh RPC.

The completed credential model replaces the software-held mTLS signing key:

- DPU-agent signs locally with a key held by the BF3/BF4 fTPM. Any supported
  environment that cannot expose an fTPM signing key supplies a hardware-backed
  holder with the same possession and lifecycle properties.
- Hosts already use TPM EK verification to anchor discovery and attestation,
  but an EK is not the JWT signing-key design. The Scout signing-key holder is
  accessible to Scout and binds its public key to the verified host identity.
- A certificate corresponding to that key is provisioned to the node and
  accompanies the JWT for API validation. The API continues to derive the
  machine identity from the verified certificate and maps it to the existing
  RBAC principal.
- The certificate must chain to an API-accepted trust anchor that does not
  depend on Vault PKI. Its issuance authorizes the binding between the fTPM
  public key and the intended machine identity; a valid chain alone is not
  sufficient to assert an arbitrary machine principal.
- Token lifetime, audience checks, TLS transport, and the dual-auth migration
  gate remain as designed in the completed JWT work.
- Machine mTLS remains supported for backward compatibility for as long as a
  deployment needs it. A site disables it only after every supported Scout and
  DPU-agent path can mint and locally re-mint tokens and replace, revoke, and
  recover the replacement signing credential and certificate.

How the certificate reaches the node is an open question
([Section 7](#7-open-questions)): an operator installs it manually, or the API
issues it through the non-Vault certificate provider from a signing request
signed by the fTPM key, in the same discovery and renewal flow that issues node
certificates for the mTLS credential. The current `CertificateProvider`
interface returns a
server-generated private key, so API issuance for a key that cannot leave the
TPM requires a signing operation on the phase-3 provider. The owner, timing,
identity authorization, renewal, replacement, revocation, and recovery
procedure are open in either case.

The admin CLI authenticates without a Vault-issued credential. The final design
may retain admin mTLS with an operator-managed non-Vault PKI or define a
replacement authentication method; either choice preserves the existing admin
authorization boundary.

### 3.3 Phase 3: KEK Custody and Certificate Issuance

#### Production non-Vault KMS

An approved production non-Vault implementation owns KEKs behind the KMS
interface. Deployment-specific implementations may use a managed cloud KMS, an
on-premises HSM or KMIP service, or a hardened Integrated deployment whose key
is supplied by a CSI secrets-store or External-Secrets mount. The selected
provider must support workload-appropriate authentication, availability,
auditability, rotation, backup restore, and recovery without placing plaintext
KEKs directly in NICo configuration.

The Integrated provider's key sources and their production restrictions are
defined in [Secrets Storage](../configuration/secrets-storage.md). A mounted-key
Integrated deployment receives the same production qualification for custody,
availability, rotation, and recovery as an external provider.

Migration reuses the existing multi-provider, routing, and re-wrap behavior:
new DEKs are wrapped by the non-Vault provider while the Transit provider remains
available to unwrap old records. Vault Transit can be removed only after all
records have been re-wrapped, recovery has been tested, no retained backup within
the restore window requires it, and the rollback window has ended.

#### Non-Vault certificate provider

Certificate vending is separate from credential storage, as defined by the
[certificate-provider separation implementation](https://github.com/NVIDIA/infra-controller/pull/2881).
The non-Vault provider implements that interface, preserves the SPIFFE ID from
which the machine principal is derived, and provides a CA rollover period in
which old and new trust roots are accepted; the API already reloads its root
bundle periodically, so the overlap is a bundle that carries both roots. The
certificate consumers are inventoried in [Section 2.1](#21-vault-touchpoints):
node certificates issued at discovery, attestation, and renewal; UFM TLS
certificates; service transport certificates issued through cert-manager; and
admin CLI client certificates. Moving node API authentication to JWT does not
remove those needs. If the fTPM certificate question in
[Section 7](#7-open-questions) resolves to API issuance, the provider interface
also gains a signing operation for keys that never leave the node.

#### Encryption convergence

Machine-identity signing-key encryption uses the same KMS-backed envelope
primitive as credential storage. The machine-identity data model and behavior
remain defined by the [JWT-SVID design](machine-identity/spiffe-svid-sdd.md);
only encryption and KEK custody converge. Each subsystem retains its own storage
while using per-record DEKs wrapped by the approved non-Vault KEK provider.

## 4. Migration and Dependency Order

1. **Adopt the phase-1 provider chain.** Import existing secrets, make
   PostgreSQL authoritative, and retain Vault read fallback until every required
   credential has been verified.
2. **Move services outside `nico-api` off the default Vault chain.**
   `dsx-exchange-consumer`, the `nico-flow` PSM and NSM containers, and any REST
   service in scope read credentials from environment, file, or mounted-secret
   sources, and the default credential chain constructs its Vault reader only
   when configured. Remove the unused Vault mounts from the `bmc-proxy` and
   `machine-a-tron` charts.
3. **Enable the node JWT migration path.** Run bearer JWTs and machine mTLS in
   parallel and verify that both produce the same principals and authorization
   results.
4. **Introduce the fTPM-backed credential.** Resolve the certificate
   provisioning questions, deploy the credential to supported nodes, and verify
   token minting, local re-minting, certificate renewal, replacement,
   revocation, and recovery before disabling machine mTLS. This step cannot
   complete until the non-Vault node certificate trust-anchor decision from
   step 6 is made.
5. **Introduce the production non-Vault KMS.** Route new wraps to it, retain
   Transit for old records, re-wrap, and test recovery. Keep both providers
   configured through the defined rollback and backup-retention windows; the
   rollback procedure is defined in
   [Secrets Storage](../configuration/secrets-storage.md).
6. **Introduce the non-Vault certificate provider.** Run an explicit trust-root
   overlap, move each remaining consumer, and retire Vault PKI only after renewal
   and rollback have been exercised. Do not retire or rotate any root out of the
   API trust bundle while node certificates still depend on it; re-anchor those
   certificates first.
7. **Make installation Vault-optional.** `helm-prereqs` phases and chart
   defaults (the cert-manager issuer, the Vault AppRole and token Secrets, and
   the `vault-cluster-info` ConfigMap) become optional so that a new site is
   installed without deploying Vault; an existing site keeps Vault only for the
   migration overlap.
8. **Resolve CLI authentication and disable Vault.** Record whether the admin
   CLI retains mTLS with non-Vault PKI or moves to another credential. Remove
   Vault from active configuration and prove startup, steady-state operation,
   rotation, backup restore, and failure recovery with Vault unavailable.
9. **Converge machine-identity encryption.** After the production non-Vault KEK
   provider is available, move machine-identity signing-key encryption to the
   shared envelope primitive. This completes the shared KEK-custody model but
   does not have to precede the Vault runtime cutover when the existing
   encryption key is already sourced through the Vault-free credential chain.

Steps 4, 5, and 6 can be developed in parallel, but their migrations and trust
retirement must be coordinated as described above. Step 7 depends on steps 2,
5, and 6 for a new site. Step 8 depends on all active Vault credential, Transit,
and PKI paths having replacements and on the CLI scope decision. Step 9 depends
on step 5 but can otherwise proceed independently.

## 5. Failure, Security, and Availability Boundaries

- Vault fallback is enabled only during an explicit migration stage. A
  steady-state Vault-free deployment does not silently reconnect to Vault.
- Loss of an fTPM key or its certificate prevents new node tokens. Machine mTLS
  is a rollout fallback and a backward-compatibility path, not the permanent
  recovery design; the certificate lifecycle defines recovery before the
  fallback is removed.
- The certificate enrollment authority must bind each approved public key and
  identity to the intended inventory record. The selected design must also
  provide individual credential disablement or revocation and a compromise
  recovery procedure before machine mTLS is removed.
- The old KMS provider remains available until no live record and no retained
  backup within the restore window references it, and until the rollback window
  ends. Re-wrap is resumable and does not change credential plaintext.
- Credential reads synchronously unwrap DEKs through the KEK provider, so an
  external KMS outage fails affected credential operations, and an Integrated
  provider whose mounted key is unavailable cannot restart or scale out while
  already-running instances continue. Runtime availability, startup
  availability, rotation by controlled restart, and recovery are therefore part
  of provider qualification. Provider mechanics are defined in
  [Secrets Storage](../configuration/secrets-storage.md) and the
  [PostgreSQL secret-storage design](postgres-secrets/README.md).
- Old CA roots remain trusted only for the bounded certificate rollover window.
  Removing a root is coordinated with certificate renewal and rollback testing.
- Credential plaintext, private keys, and bearer tokens are never logged.
  Production KEKs come from mounted files, environment sources, or an external
  KMS; [Secrets Storage](../configuration/secrets-storage.md) defines why inline
  key material is limited to development and test.
- Provider credentials use workload identity or mounted secret sources where
  supported and are independently rotatable from the data they protect.
- Multi-replica NICo deployments use shared PostgreSQL state and highly
  available KMS and CA endpoints; no replica owns unique recovery material.

## 6. Completion Criteria

The overall effort is complete when a supported site can:

- install a new site with `helm-prereqs` and the Helm charts without deploying
  Vault/OpenBao;
- start and run every NICo service, including those outside `nico-api`, with
  Vault/OpenBao unavailable;
- read, write, rotate, back up, and restore credentials using PostgreSQL and a
  qualified production non-Vault KEK provider;
- bootstrap and authenticate Scout and DPU-agent, locally re-mint their tokens,
  and rotate, revoke, or recover their signing credentials without a
  Vault-issued mTLS certificate;
- authenticate the admin CLI with the selected Vault-free credential while
  preserving its authorization boundary;
- issue and rotate every still-required certificate through a non-Vault
  provider;
- preserve machine identity and RBAC behavior through migration;
- roll forward from a Vault-backed deployment without credential loss or an
  authentication outage;
- demonstrate rollback at every provider-overlap stage before retiring the old
  credential, KEK, or CA trust path; and
- protect machine-identity signing keys with the shared envelope and the
  qualified non-Vault KEK provider.

## 7. Open Questions

1. How is the certificate for the fTPM signing key provisioned: installed
   manually by an operator, or issued by the API through the non-Vault
   certificate provider from a request signed by the fTPM key? In either case,
   who performs it, at what point in the hardware lifecycle, and what
   authorizes its machine identity?
2. How are that certificate and fTPM key renewed, replaced, revoked, and
   recovered without restoring machine mTLS as a permanent dependency?
3. Which supported hardware and boot environments expose the required fTPM
   signing capabilities to Scout and DPU-agent? For Scout, can a TPM-resident
   signing key be enrolled through the existing host TPM identity path, and what
   credential holder is used where that is unavailable?
4. Does phase 2 retain admin CLI mTLS with an operator-managed non-Vault PKI, or
   replace it with another authentication method?
5. Which production KMS, HSM, KMIP, or hardened Integrated deployment is
   qualified first, and what is the minimum supported recovery configuration?
6. Which non-Vault CA backs the certificate-provider interface, and which
   cert-manager issuer replaces `vault-nico-issuer` for service transport
   certificates?
7. Are the REST API services and the `nico-flow` PSM and NSM credential paths in
   scope of phase 3, or does a separate effort own them?

## 8. Implementation Status

This section is a status snapshot dated 2026-09-02. Sections 1 through 7 define
the end-state design and remain independent of implementation order. Phase 1
([#195](https://github.com/NVIDIA/infra-controller/issues/195)) is complete
apart from this document
([#3251](https://github.com/NVIDIA/infra-controller/issues/3251)) and is with
QA; remaining credential-related work is tracked under
[#5200](https://github.com/NVIDIA/infra-controller/issues/5200). The tables
below record the intentional intermediate states created when one epic lands
before a dependency owned by another epic.

### 8.1 Intermediate States Between Epics

| Boundary | Intermediate state | Resolving work |
| :--- | :--- | :--- |
| Phase 1 credential-storage boundary | After [#195](https://github.com/NVIDIA/infra-controller/issues/195), credentials can be authoritative in PostgreSQL while their per-record DEKs are still wrapped by a KEK in Vault/OpenBao Transit. PostgreSQL removes Vault as the credential database but does not yet remove the transitive KEK dependency. | [#3253](https://github.com/NVIDIA/infra-controller/issues/3253) supplies the production non-Vault KEK provider; the migration then routes new wraps to it, re-wraps live records, and retains Transit only through the rollback and backup-retention windows. |
| Services outside `nico-api` | Phase 1 made the `nico-api` chain Vault-optional, but the default chain used by `dsx-exchange-consumer` still constructs a Vault client, the `nico-flow` PSM and NSM containers still take Vault tokens, and the `bmc-proxy` and `machine-a-tron` charts still mount unused Vault Secrets. | A new subtask under [#5200](https://github.com/NVIDIA/infra-controller/issues/5200) makes the Vault reader optional and defines the non-Vault sources listed in [Section 2.1](#21-vault-touchpoints). |
| Initial phase 2 JWT boundary | [#355](https://github.com/NVIDIA/infra-controller/issues/355) provides bearer JWTs and permits machine mTLS to be disabled at the transport-authentication layer, but the JWT is still signed with the Vault-issued mTLS certificate key and carries that certificate chain. | [#5272](https://github.com/NVIDIA/infra-controller/issues/5272) replaces the DPU signing holder with BF3/BF4 fTPM. Certificate provisioning and lifecycle and the Scout-side holder still need dedicated subtasks under [#5199](https://github.com/NVIDIA/infra-controller/issues/5199). |
| Node credential before PKI retirement | The fTPM credential can replace the Vault-issued node key only while its certificate chains to an API trust anchor. Vault PKI cannot be retired merely because token signing moved into the fTPM. | [#5272](https://github.com/NVIDIA/infra-controller/issues/5272) owns the signing holder. A new certificate-provider subtask under [#5200](https://github.com/NVIDIA/infra-controller/issues/5200) must supply the lasting trust anchor and rollover plan; the provisioning and lifecycle questions require phase-2 tracking. |
| Phase 2 node boundary versus CLI | Scout and DPU-agent can be Vault-free while the admin CLI still uses mTLS. An operator-managed external admin CA removes the CLI's Vault dependency but does not resolve whether [#5199](https://github.com/NVIDIA/infra-controller/issues/5199) intends to remove CLI mTLS itself. | A new subtask under #5199 must record and implement the decision to retain non-Vault admin mTLS or replace it. |
| Certificate-provider separation boundary | [#2880](https://github.com/NVIDIA/infra-controller/issues/2880) separates certificate vending from credential storage, but the production certificate-provider implementations remain Vault-backed. | A new implementation subtask under [#5200](https://github.com/NVIDIA/infra-controller/issues/5200) must add the non-Vault provider, migrate the consumers in [Section 2.1](#21-vault-touchpoints), and roll over trust roots. |
| Non-Vault KEK before encryption convergence | After [#3253](https://github.com/NVIDIA/infra-controller/issues/3253), the PostgreSQL envelope and the machine-identity encryption-key credential can both be protected without Vault, but machine-identity signing keys still use a separate encryption primitive. | [#3255](https://github.com/NVIDIA/infra-controller/issues/3255) converges machine-identity encryption on the shared KMS envelope. This completes the target custody model but does not independently block the Vault runtime cutover. |

### 8.2 Work-Item Status

| Area | Status at this snapshot | Tracking |
| :--- | :--- | :--- |
| PostgreSQL credential store, design, and migration | Implemented; detailed behavior remains in the existing design | [#353](https://github.com/NVIDIA/infra-controller/issues/353), [#354](https://github.com/NVIDIA/infra-controller/issues/354), [PostgreSQL secret-storage design](postgres-secrets/README.md) |
| Operator file/environment foundation | Implemented, including file-backed UFM credentials with live reload and an authoritative local mode; an operator page for the UFM sources is a documentation follow-up | [#357](https://github.com/NVIDIA/infra-controller/issues/357), [#1837](https://github.com/NVIDIA/infra-controller/issues/1837) |
| Remaining credential-consumer adoption | `nico-api` consumers use the credential abstraction; open items are whether NMX-M needs the authoritative local source and live reload that #1837 gave UFM, and the services outside `nico-api` in [Section 2.1](#21-vault-touchpoints) | New subtask needed under [#5200](https://github.com/NVIDIA/infra-controller/issues/5200) |
| NVSwitch OS credentials | Closed as not planned: NSM is deprecated in favor of RMS, which reads switch credentials from NICo | [#1852](https://github.com/NVIDIA/infra-controller/issues/1852) |
| Node bearer JWT and dual-auth rollout | Implemented, with the Vault-issued mTLS certificate key as the intermediate signing credential | [#355](https://github.com/NVIDIA/infra-controller/issues/355), [Node-auth bearer JWTs](machine-identity/node-auth-jwt.md) |
| fTPM signing credential | Open for BF3/BF4; certificate provisioning and lifecycle and the Scout holder lack dedicated tracking | [#5272](https://github.com/NVIDIA/infra-controller/issues/5272); new subtasks needed under [#5199](https://github.com/NVIDIA/infra-controller/issues/5199) |
| IRoT identity and API-issued refresh | Never merged; closed as not planned because the DPU OS cannot access the IRoT key and so cannot prove possession; the fTPM in #5272 replaces it, and the merged JWT path re-mints locally | [#2917](https://github.com/NVIDIA/infra-controller/issues/2917), [#3254](https://github.com/NVIDIA/infra-controller/issues/3254) |
| Admin CLI authentication | Open scope decision named by the epic but absent from its subtasks | New subtask needed under [#5199](https://github.com/NVIDIA/infra-controller/issues/5199) |
| Certificate-provider separation | Implemented; production providers remain Vault-backed | [#2880](https://github.com/NVIDIA/infra-controller/issues/2880), [implementation](https://github.com/NVIDIA/infra-controller/pull/2881) |
| Non-Vault certificate provider | Open with no dedicated tracking issue | New subtask needed under [#5200](https://github.com/NVIDIA/infra-controller/issues/5200) |
| Vault-optional installation | Open with no dedicated tracking issue | New subtask needed under [#5200](https://github.com/NVIDIA/infra-controller/issues/5200) |
| Production non-Vault KEK provider | Open | [#3253](https://github.com/NVIDIA/infra-controller/issues/3253) |
| Machine-identity encryption convergence | Open after #3253; not an independent Vault-cutover gate | [#3255](https://github.com/NVIDIA/infra-controller/issues/3255) |
| Shared UFM/NMX-C cache lifecycle | Open, non-blocking refactor that preserves #1837 behavior | [#5516](https://github.com/NVIDIA/infra-controller/issues/5516) |
| Overall high-level design | This document | [#3251](https://github.com/NVIDIA/infra-controller/issues/3251) |
