# Node-Auth: Self-Signed Bearer JWTs for Scout and DPU-Agent

Design for [#355](https://github.com/NVIDIA/infra-controller/issues/355)
(sub-issue of the Vault-elimination epic
[#195](https://github.com/NVIDIA/infra-controller/issues/195)): Scout and the
DPU-agent authenticate to the API with short-lived bearer JWTs alongside —
and eventually instead of — mTLS client certificates.

Nodes sign their own tokens with the private key of their **existing** mTLS
client certificate. There is no new key material anywhere, no server-side
signing key or key storage, no issuance or refresh RPCs, and no dependency on
the `machine_identity` (tenant JWT-SVID) subsystem. On a DPU only the
dpu-agent ever holds that key; co-located NICo pods get finished tokens from
it over a local unix socket (see [Key distribution on DPF](#key-distribution-on-dpf-the-agent-is-the-token-broker)).
Approaches that were weighed and rejected are recorded under
[Designs not used](#designs-not-used).

It is distinct from the tenant-facing [SPIFFE JWT-SVID design](spiffe-svid-sdd.md):
that issues identity tokens *to tenant workloads* via IMDS; this design covers
how *NICo's own node agents* authenticate to the NICo API.

## How it works

```text
node (scout / dpu-agent)                      nico-api
------------------------                      --------
has /opt/forge/machine_cert.pem  ── x5c ──►   1. verify x5c chain against the
and /opt/forge/machine_cert.key                  client-cert root CA (same roots
                                                 as the TLS listener)
mint ES256 JWT signed with the                2. verify JWT signature with the
cert's own key, 5-min TTL,                       verified leaf's public key
cert chain in the x5c header                  3. enforce exp / iat / aud, bounded
                                                 lifetime
attach as Authorization: Bearer               4. SPIFFE-validate the leaf; map its
on every gRPC request                            URI SAN through the same
                                                 SpiffeContext as mTLS certs
                                              ⇒ identical machine principal, RBAC
                                                 unchanged
```

Key-less co-located services (fmds) never touch the cert or key at all: they
ask the dpu-agent for its current token over a unix socket and attach that
same header.

```text
fmds pod                          dpu-agent                nico-api
--------                          ---------                --------
no key, no cert    ──socket──►   holds the key,   ── same bearer token ──►
GetNodeToken                      mints as above           (identical
(cached, refreshed                                          verification)
 in the background)
```

## Auth flow: new DPU → first authorized gRPC call

**Provisioning & bootstrap (no credentials yet)**

- A new DPU is provisioned (BFB installed via DPF); the `forge-dpu-agent` DPF
  service starts on it with only two auth-relevant inputs from its config: the
  API endpoint and the root CA bundle (`forge_system.root_ca`). The cert/key
  files at `/opt/forge/machine_cert.pem` / `machine_cert.key` don't exist yet.
- The agent opens a TLS connection to `nico-api` that is **server-auth only**
  — it verifies the API's cert against the root CA but presents no client
  credential (the API listener uses `allow_unauthenticated()`, so the
  connection is accepted with an anonymous principal).

**First credential: the machine certificate**

- The agent calls `DiscoverMachine`
  (`host-support/registration.rs::register_machine`) carrying its hardware
  enumeration (`DiscoveryInfo`); this RPC is reachable pre-credential by
  design.
- The API registers/matches the machine and returns a `machine_certificate`
  in the response: a Vault-PKI-issued EC P-256 leaf whose SAN is the machine's
  SPIFFE URI (`spiffe://<trust-domain>/<ns>/machine/<machine-id>`), plus the
  issuing CA and private key. (On attestation-enabled sites, hosts get this
  via `AttestQuote` after a TPM challenge instead; DPUs take the discovery
  path.)
- `write_certs` persists leaf+issuing-CA to `/opt/forge/machine_cert.pem` and
  the key to `/opt/forge/machine_cert.key`. **This existing cert key is the
  JWT signing key — nothing else is ever created.**

**Minting the JWT (client side, `rpc::node_jwt`)**

- The agent's gRPC client was built with
  `ForgeClientConfig::new(root_ca, ClientCert{...}).with_node_jwt()`, so a
  `NodeJwtMinter` watches those two file paths.
- On the next outgoing RPC, the minter reads cert+key from disk (re-encoding
  Vault's SEC1 key PEM to PKCS#8) and signs an **ES256 JWT**: header
  `{alg: ES256, x5c: [leaf, issuing CA]}`, claims
  `{sub: <SPIFFE URI from its own cert SAN>, aud: <configured audience>,
  iat: now, exp: now+300s}`. The token is cached and re-minted when < 60 s
  remain — no refresh RPC, and cert renewal is picked up automatically
  because the files are re-read at each mint.
- Renewal writes the certificate and the key in two separate operations, so
  the minter compares the key's public half against the one certified by the
  leaf before signing. A mismatch (a mint landing between the two writes)
  fails the mint rather than caching a token the API will reject.
- `BearerAuthService` stamps `Authorization: Bearer <jwt>` onto the request.
  (The TLS channel may still present the client cert too — dual-support; each
  is sufficient alone.)

**Validation (server side, requires `[node_auth] enabled = true` + TLS listener)**

- The authn middleware sees the Bearer header and hands it to
  `NodeJwtValidator`, which checks in order:
  - header `alg` is exactly ES256 (no algorithm substitution);
  - the `x5c` chain verifies against the **same root CA file the TLS listener
    uses for client certs** (`[tls] root_cafile_path`) — path building,
    validity window, client-auth EKU;
  - the JWT signature verifies with the *verified leaf's* public key;
  - claims: `exp`/`iat`/`aud` enforced, and lifetime bounded by
    `max_token_ttl_sec` (default 900 s) so a client can't stretch `exp`;
  - the leaf passes SPIFFE validation (leaf-only, single URI SAN), and `sub`
    must equal that SAN — identity comes from the verified cert, never from
    the claim.

**Authorization & the first call**

- The validated SPIFFE URI is mapped through the same `SpiffeContext` as mTLS
  certs → a `SpiffeMachineIdentifier` principal, byte-identical to what the
  cert path would have minted.
- Casbin RBAC evaluates that principal exactly as before (machine class →
  Agent/Scout role rules) — **no RBAC changes** — and the handler executes.
  That is the first authorized gRPC call on bearer auth.

Note: the very first *authorized* call after discovery could ride either
credential, since the agent holds both from the same moment — the JWT only
becomes load-bearing once `mtls_enabled = false`.

## Q1 — How does the agent get a private key that is trusted to create the JWT?

**It already has one.** The node's Vault-issued mTLS client certificate key
(`/opt/forge/machine_cert.key`, EC P-256 — Vault PKI role `key_type=ec,
key_bits=256`) signs the JWT, and the certificate itself rides along in the
token's `x5c` header (RFC 7515 §4.1.6). The key is trusted because the
certificate chains to the root CA the API already trusts for client certs —
the JWT is effectively "mTLS at the application layer".

Bootstrapping is unchanged: a machine obtains its first certificate through
the existing discovery/attestation flow (`DiscoverMachine` / `AttestQuote`
respond with the machine certificate — see the auth-flow walkthrough above),
and from that moment it can mint tokens. Minting is best-effort: before the
cert exists, requests simply carry no bearer header.

## Q2 — JWT side by side with mTLS

The authn middleware (`CertDescriptionMiddleware` in `crates/authn`) mints
principals from **both** sources on every request: the TLS-layer client cert,
and the `Authorization: Bearer` token (validated by `NodeJwtValidator`). Both
paths converge on the same SPIFFE URI → `SpiffeMachineIdentifier` mapping
through the same `SpiffeContext`, so RBAC (Casbin policy, role mapping) is
completely unchanged. A node presenting both credentials gets the same
principal twice — harmless. Clients attach the bearer token unconditionally
(`ForgeClientConfig::with_node_jwt()` in scout and dpu-agent); a server with
node-auth disabled ignores the header, so rollout order doesn't matter.

## Q3 — JWT off by default, configured in the API config

```toml
[node_auth]
enabled = false          # master switch for accepting bearer JWTs
audience = "nico-api"    # `aud` required on presented tokens
max_token_ttl_sec = 900  # upper bound on client-chosen lifetimes (cap 86400)
```

When `enabled = true`, startup requires a TLS listener (bearer tokens are
never accepted over plaintext) and a readable `[tls] root_cafile_path`;
missing prerequisites fail startup rather than silently degrading. The whole
preflight runs *before* DPF resource creation, so a misconfiguration can't
mutate cluster state on its way to failing.

`audience` is the one value that must be set on **both** ends: the API
validates `aud` against it, and each node stamps it. Nodes take it from their
own config — scout via `--node-auth-audience`, the agent via `[forge-system]
node-auth-audience` (or the `--node-auth-audience` flag, which is how DPF
deploys it, since containerized agents run with no config file and the API
templates the value from its own `[node_auth] audience`). A site that changes
one end and not the other has every token rejected.

## Q4 — mTLS on by default, disableable in the API config

```toml
[node_auth]
mtls_enabled = true
```

When `mtls_enabled = false`, the middleware stops minting machine principals
from client certificates — bearer JWTs become the only node auth path. The
gate is scoped to **machine** certs: service and admin-CLI certs on the same
listener are unaffected. `enabled = false` + `mtls_enabled = false` is
rejected at startup (node lockout).

Note the trust chain is still the certificate PKI: disabling mTLS here
disables the *transport-layer* cert authentication, not cert issuance. Nodes
must keep renewing certificates because the JWT is signed by the cert key.

## Q5 — Key regeneration and public-key exchange

**Regeneration** is the existing client-certificate renewal: when
`ClientCertRenewer` rotates the cert/key files, the minter picks the new pair
up on its next re-mint (it re-reads both files from disk each time). No
coordination, no state.

**Public-key exchange: the x5c header.** Every token carries the certificate
chain that vouches for its signing key, and the API verifies that chain
against the root CA bundle it already holds (`[tls] root_cafile_path`). There
is no JWKS endpoint, no key registry, and no key distribution problem — CA
rotation is handled wherever the root bundle is handled today.

**CA rotation** moves both consumers of that bundle together. The TLS
listener already re-reads the file every five minutes for cert-manager
rotations; the validator's trust anchors are held behind a lock and refreshed
on that same tick, so a token chaining to a freshly rotated CA is accepted
without an API restart. A failed reload keeps the previous anchors — a bundle
caught mid-write must not disarm node auth.

**Compromise response** is likewise the PKI's: a stolen key/cert pair is the
same incident as a stolen mTLS cert today. Tokens age out in minutes
(`exp - iat ≤ max_token_ttl_sec`, client mints 5-minute tokens), and that
expiry — together with chain and EKU validation — is what actually bounds a
stolen key. Revocation does not: the validator calls
`allow_unknown_revocation_status()`, so a holder of the private key keeps
minting acceptable tokens until the certificate itself expires. Cutting a
compromised key off sooner needs revocation checking we do not do yet.

## Q6 — JWT best-practice checklist

| Practice | How it's honored |
| --- | --- |
| Asymmetric signing, no `alg` confusion | ES256 only; both the header check and `Validation` pin the algorithm, so `none`/HS256 substitution is rejected. |
| Identity never comes from claims | The principal derives from the **chain-verified certificate's SPIFFE SAN**; `sub` is only cross-checked against it. A forged `sub` buys nothing. |
| Short-lived tokens | Clients mint 300 s tokens; the server enforces `exp - iat` and `exp - now` ≤ `max_token_ttl_sec` (default 900 s, hard cap 86400), so a client cannot stretch `exp`. |
| `exp` / `iat` / `aud` enforced | Required claims; validated by `jsonwebtoken` plus the bounded-lifetime check. |
| Chain validation, not pinning | `x5c` verified with rustls `WebPkiClientVerifier` (path building, validity window, client-auth EKU) against the same roots as the TLS listener. |
| SPIFFE leaf constraints | `carbide_authn::validate_x509_certificate` re-checks leaf-ness, key usage, and the single-URI-SAN rule — same code path as mTLS certs. |
| No bearer tokens over plaintext | Enforced at both ends. Server: startup refuses `enabled = true` on a non-TLS listener, the middleware only installs the validator when the listener is TLS-terminated, and a failed acceptor rebuild keeps the previous acceptor rather than falling back to cleartext. Client: `with_token_provider` implies `require_tls_enforcement`, and building a token client against a non-HTTPS URL is an error. |
| No key material at rest beyond the PKI | The server holds no signing key; the client holds only what it already had, and `write_certs` persists the key file owner-only (0600). Credentials never in logs (both token caches have a redacting `Debug`). |
| Least exposure for the signing key | On a DPU the key stays in the dpu-agent alone; consumers get finished short-lived tokens over a local socket and never mount the credentials directory. |

## Component map

| Piece | Where |
| --- | --- |
| Client mint + cache + header injection | `crates/rpc/src/node_jwt.rs` (`NodeJwtMinter`, `BearerAuthService`, `NodeTokenProvider`) |
| Client opt-in | `ForgeClientConfig::with_node_jwt()` / `with_token_provider()` (`crates/rpc/src/forge_tls_client.rs`); called in scout `client.rs` and dpu-agent `lib.rs` |
| Key-less token source | `crates/rpc/src/node_token_socket.rs` (`SocketTokenSource`), consumed by fmds via `--node-token-socket` |
| Broker service | `AgentLocal/GetNodeToken` in `crates/rpc/proto/agent_local.proto`, served by `crates/agent/src/local_api.rs` |
| Server validation | `crates/api-core/src/node_auth.rs` (`NodeJwtValidator`) |
| Config | `NodeAuthConfig` in `crates/api-core/src/cfg/file.rs` (`[node_auth]`); node side in `crates/host-support/src/agent_config.rs` and the two `command_line.rs` |
| Middleware hook | `BearerTokenAuthenticator` trait + machine-cert gate in `crates/authn/src/middleware.rs` |
| Wiring | `crates/api-core/src/setup.rs` (preflight, validator construction), `listener.rs` (middleware install, trust-anchor reload), `dpf_services.rs` (fmds token mode) |
| Charts | `bluefield/charts/nico-fmds` (`useNodeTokens`), `bluefield/charts/nico-dpu-agent` |

All of it logs under one target: `RUST_LOG=node_auth=debug` turns on the
whole feature's tracing, and every message carries a `node-auth:` prefix.

## Key distribution on DPF: the agent is the token broker

The machine cert/key live at `/opt/forge` on the DPU, a hostPath directory
several NICo pods mount. Rather than share the key with each of them, the
dpu-agent is the only holder and hands out finished tokens.

- **The socket.** The agent serves `AgentLocal/GetNodeToken` on a unix socket
  at `/opt/forge/run/agent.sock`, mode 0600 — a dedicated `run/` subdirectory
  so a consumer can mount just that path read-write (`connect(2)` needs write
  access to the socket inode) while credentials stay elsewhere. `bind` creates
  the socket at umask permissions and the 0600 chmod only lands afterwards, so
  the directory — not the socket — is what closes that window; the agent
  therefore requires the socket's parent to be dedicated, creating it `0700` or
  refusing a directory that holds anything else. (Without that rule,
  `local-api-socket = /run/agent.sock` would take `/run` to `0700` and lock
  every non-root service on the box out of its runtime files.) The path is
  configurable via `[forge-system] local-api-socket`; the server retries
  forever rather than dying once, since a bare-metal boot can start the agent
  before its directory exists. This socket is the consolidation point for
  future agent ↔ co-located-service traffic, in place of new sockets, ports,
  or file drops.
- **The consumer.** `SocketTokenSource` implements the same
  `NodeTokenProvider` trait as the minter, so a client built with
  `with_token_provider()` is indistinguishable on the wire from one that
  minted its own. A background task keeps the cached token fresh (refresh at
  60 s remaining, request-path cutoff at half that, per-attempt deadline
  covering connect + RPC); the request path never blocks, and before the
  first successful fetch requests simply carry no bearer header.
- **The trust anchor, without the key.** fmds still needs the root CA, so the
  agent mirrors it to `<certsDir>/pub/`, a directory holding nothing else.
  Token-mode fmds pods mount `pub/` plus `run/` and **do not reference the
  credentials volume at all**, not even in the init container — the machine
  key is absent from the pod rather than merely read-only, which matters
  because the container runs as UID 0. It is a directory mount, not a
  `subPath`, so the atomic-rename CA replacement still propagates into a
  running pod. The agent republishes on every start as well as from the init
  container, so a CA replaced out of band propagates too.
- **The switch.** fmds helm values are rendered by the API, so `useNodeTokens`
  is derived from the one setting that makes tokens meaningful: `[node_auth]
  enabled`. With node-auth off, the chart renders exactly as before. Rollout
  note: enabling it requires an agent image that serves the socket, so
  agent and fmds images must be deployed together.

Scope: this covers *authentication to nico-api*. otelcol also uses the machine
cert for TLS client auth to its OTLP gateway, which a nico-api bearer token
cannot replace, so the key only fully disappears from other pods once that
ingest path has its own credential story.

## Design decisions (resolved questions)

1. **How does the server learn the public key?** → from the token itself
   (`x5c`), verified against the existing root CA — the one key-distribution
   mechanism the system already operates.
2. **Why not drop mTLS immediately, since the JWT proves the same key?** →
   dual-support de-risks rollout and keeps requirement 4 orthogonal; and the
   JWT still depends on the cert PKI, so cert issuance must outlive transport
   mTLS.
3. **Client-side enable knob?** → none. Nodes always mint when they hold a
   cert; a disabled server ignores the header (verified by middleware test).
   One switch (`[node_auth] enabled`) controls the feature. The audience is
   the sole value that must agree on both ends.
4. **Replay window** → a captured token is replayable for ≤ 5 minutes against
   the same API over TLS only. Accepted; `jti`/nonce tracking or DPoP-style
   proof-of-possession is the hardening path if needed.
5. **RSA machine certs** → not supported (Vault PKI role is EC P-256
   everywhere); the validator rejects non-EC leaves with a clear debug reason.

## Known issues

**Disabling `[node_auth]` after fmds has been in token mode is unsequenced.**
The two halves of the switch take effect on different clocks:

- The API stops accepting bearer tokens *immediately*, when it restarts with
  `enabled = false`.
- fmds returns to cert mode only *eventually*. The re-apply is real —
  `create_initialization_objects` upserts the DPUServiceConfiguration by
  forced server-side apply, so the new `useNodeTokens: false` does land — but
  DPF then has to re-render and roll the DaemonSet across the fleet.

In between, fmds pods are still running token mode with no client cert and
tokens the API now rejects: `phone_home` and machine-identity signing take
401s until the roll reaches each node. Config serving and instance metadata
are unaffected, and it self-heals once the roll completes.

Nothing is corrupted by the transition. The agent writes `machine_cert.pem` /
`.key` and the base-path root CA unconditionally, in both modes, so cert mode
works the moment a pod rolls; leftover `pub/` and `run/` directories are
inert.

There is no way to stage it today, because `useNodeTokens` is derived from
`[node_auth] enabled` alone. The safe order — move fmds off tokens, confirm
the roll landed, *then* stop accepting tokens at the API — would need an
explicit per-service override defaulting to the derived value. The enable
direction has the mirror window but fails safe: the init container blocks
waiting for the CA in `pub/` rather than starting into a broken state.

## Designs not used

**Server-issued tokens.** A site-level signing key in the credential store, a
`RefreshNodeToken` RPC, and DPU device identity as the refresh anchor. It
brings back everything this design deletes: a server-side key to store,
rotate, and share across HA replicas; issuance and refresh RPCs to build,
version, and rate-limit; and a bootstrap question of its own (what
credential authorizes the *first* refresh). Reusing the node's existing
client-cert key gets the same authenticated principal with no new secret
anywhere. Worth revisiting only if per-node keys are removed from the
architecture, at which point nothing is left to self-sign with.

**A JWKS endpoint or key registry.** The obvious way to publish per-node
public keys, and unnecessary: `x5c` carries the certificate with every token
and the API already holds the root CA that vouches for it. A registry would
add a distribution channel that can go stale, be unreachable, or disagree
with the PKI — and CA rotation would have to be handled in two places instead
of one.

**Reusing the tenant JWT-SVID subsystem.** `machine_identity` issues SPIFFE
JWT-SVIDs to *tenant workloads* via IMDS. Node agents authenticating to the
NICo API is a different problem with a different trust root, and coupling
them would make NICo's own control plane depend on a tenant-facing service
being healthy.

**Kubernetes Secret for the machine key.** Secret mounts are tmpfs, so the
key stops touching DPU flash, and sharing becomes explicit, per-pod, and
auditable through the K8s API. But in DPF the DPU-cluster control plane
(kamaji-hosted etcd) runs on the x86 management cluster, so the key gains a
durable copy — plus backups — *off the DPU*, requiring etcd encryption at
rest to be guaranteed; the agent needs new K8s API rights to create and
update the Secret; and scout (pre-DPF, live-image) can't use this path at
all, so the file mechanism would survive alongside it. The token broker
addresses the same concern — key exposure surface — without moving the key
anywhere, so this became moot rather than merely deferred.

**Sharing the key by hostPath, read-only.** What token mode replaced. A
read-only mount of the credentials directory stops nothing: the container
runs as UID 0 and can read `machine_cert.key` regardless. Whether the mount
is read-only is not the control; whether the file is in the pod's namespace
at all is.

**Mounting just the CA file by `subPath`.** A tempting one-line fix for the
above — mount the single file rather than the directory. `subPath`
bind-mounts an inode, and `install_bootstrap_ca` replaces the CA by atomic
rename, so a running pod would keep the old anchor forever and silently fail
after a CA rotation. Hence the dedicated `pub/` directory.

**A network endpoint for the broker.** There is precedent for it — the agent
already dials `nico-dhcp-server` over gRPC through a k8s `Service` — but the
token broker is a different kind of service, and a port is the wrong shape
for it:

- *The socket is the authorization check.* `GetNodeToken` ignores its request
  entirely: there is no authentication in the handler, because anyone who can
  connect is already on the node with the path mounted. On a TCP port that
  same RPC hands a full machine identity to every pod in the DPU cluster, and
  to anything that can route to the DPU.
- *TLS can't fix that.* Protecting the endpoint means mTLS with the machine
  cert — which the consumer does not have, that being the entire premise. The
  transport cannot be secured by the credential it exists to distribute, so a
  port needs a second credential system to bootstrap the first. The SPIFFE
  Workload API is a unix socket for this reason.
- *Locality.* Agent and consumer are DaemonSets on the same node; the call is
  same-node by construction. A `Service` routes it through cluster DNS and a
  VIP whose control plane (kamaji-hosted etcd) runs on the x86 management
  cluster — making "can this node authenticate at all" depend on remote
  infrastructure. A socket is a path.
- *No listening port* to firewall or expose by accident, which matters on a
  DPU where `nico-otelcol` runs with `hostNetwork: true`.

The cost of the choice is real: `connect(2)` needs write access to the socket
inode, which is why the socket sits in its own `run/` subdirectory on a
read-write mount. And it serves co-located consumers only — anything off-DPU
needing a node token is not covered by this design.

Note what mode 0600 does and does not buy. Everything on the DPU runs as
root, so the UID check separates nobody; the real control is which pods mount
the directory. The gain over sharing the key is the blast radius of a leak —
a five-minute token instead of a long-lived private key — not a hard
boundary.

**Certificate revocation checking.** Not implemented — see Q5. Token expiry
and the certificate's own lifetime are what bound a compromised key; if the
incident model needs a faster cutoff than that, revocation is the work, and
this design does not do it.
