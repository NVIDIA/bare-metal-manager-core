# Secrets Storage <Badge intent="info">v2.0</Badge> <Badge intent="launch" minimal>New</Badge>

NICo keeps the credentials it manages (BMC logins, switch and UFM accounts, factory defaults, and so on) in a credentials store. Vault is the historical and default backend. NICo can also store credentials in Postgres, encrypted per credential with envelope encryption, and can read both backends side by side; that combination is what makes a gradual, reversible migration off Vault possible.

This page covers the `[secrets]` section of the `nico-api` config, the Vault-to-Postgres migration walk, and key rotation. If `[secrets]` is absent, nothing here applies: credentials flow through the classic environment, file, and Vault chain.

## How It Works

The credentials store behaves as follows:

- Reads walk a chain, and the first backend with an answer wins. The local overrides (environment and file, when their `[credentials.*]` sections are enabled) are always consulted first; then each backend in `backends`, in the order you list them.
- Writes go to exactly one backend: `writer`.
- The Postgres store is an append-only journal. The newest entry for a path is the credential, and an empty password reads as "no credential". Each entry's value is encrypted with its own data encryption key (DEK), and the DEK is wrapped by a key encryption key (KEK) held outside the database by a key management service (KMS) provider.
- Reads never consult the routing table. Every stored entry records which KEK wrapped it, so rotating a key redirects new writes without touching what is already readable.
- Vault keeps serving public key infrastructure (PKI) certificates regardless of this chain. Retiring Vault from credential reads does not retire it from PKI.

The secrets KEK is the secrets store's own key; it is unrelated to the machine-identity KEK (refer to [Machine Identity](machine_identity.md)).

## Configuration Reference

The `[secrets]` section enables the Postgres backend and sets how credentials flow. Adding the section with only the required fields changes nothing by itself: the defaults keep the existing chain (environment, file, Vault) and keep writes in Vault.

These are the `[secrets]` fields:

| Field | What it does | Default |
|---|---|---|
| `kms` | The KMS providers that wrap DEKs, and which one is active for new writes. Required. | (required) |
| `routing` | Maps path prefixes to the `kek_id` that encrypts new writes under them, longest prefix winning. A `"/"` catch-all entry is required. | (required) |
| `backends` | The backend read order, highest priority first. An empty list, or a backend named twice, fails the boot. | `["vault"]` |
| `writer` | Where new credential writes go: `"vault"` or `"postgres"`. | `"vault"` |
| `import_from` | A source backend to import from, once, at startup. Only `"vault"` is supported. Unset means nothing to import. | unset |
| `import_approach` | How the import treats paths that already exist in Postgres: `"missing_only"` skips them; `"all"` appends fresh journal entries. | `"missing_only"` |

The following example reads Postgres first with Vault as the fallback, using a local integrated KEK:

```toml
[secrets]
backends = ["postgres", "vault"]
writer = "postgres"
import_from = "vault"

[secrets.kms]
active = "site"

[secrets.kms.providers.site]
type = "integrated"
keys = { "site-kek-1" = { env = "NICO_SECRETS_KEK" } }

[secrets.routing]
"/" = "site-kek-1"
```

### KMS Providers

Providers are named. The `active` provider wraps DEKs for new writes; every configured provider answers unwraps for the `kek_id`s it holds, which is what keeps old entries readable while keys move. Two provider types exist:

- `integrated`: local key material. `keys` maps each `kek_id` to where its base64-encoded 256-bit key loads from: `{ env = "NAME" }`, `{ file = "/path" }`, or `{ value = "..." }`. Key material never appears in the config, only where to find it. Prefer `env` or `file` for real keys: the config file is debug-logged at startup and served on the web debug page, so an inline `value` lands in both.
- `transit`: Vault or OpenBao Transit, which wraps and unwraps DEKs server-side, so KEK material never leaves the KMS. `keys` lists the Transit key names this provider answers for, and `transit_mount` overrides the secrets-engine mount (default `"transit"`). Transit requires a static Vault token in the credential config; the Kubernetes service-account login flow is not supported for Transit yet.

NICo validates all of this at startup, before any writes or imports: every routed `kek_id` must exist in the active provider (new writes all wrap there), a `kek_id` cannot appear in two providers, and a bad section fails the boot.

### Routing

`[secrets.routing]` chooses which KEK wraps new writes under each path prefix, longest prefix winning, with `"/"` as the required catch-all:

```toml
[secrets.routing]
"/" = "default-key"
"machines/bmc" = "bmc-key"
```

Reads ignore routing entirely, so editing it is always safe for existing data. Pair a routing change with a re-wrap (below) when the goal is to move existing entries onto the new key.

## Migrating from Vault to Postgres

The migration is a config walk. Each step is a config change plus a restart, and each step reverses by putting the previous config back: the journal is append-only and the import leaves Vault untouched.

1. **Stage the section.** Add `[secrets]` with `kms` and `routing` filled in and everything else at defaults. Reads and writes flow exactly as before.
2. **Import once.** Set `import_from = "vault"`. At the next startup, one replica copies every Vault credential into Postgres; a journal marker and a session lock keep the import one-time and multi-replica safe. The default `missing_only` approach is idempotent, so a crash mid-import re-runs at the next boot and converges. If enumerating the source fails, the import aborts before writing anything.
3. **Read Postgres first.** Set `backends = ["postgres", "vault"]` and `writer = "postgres"`. Postgres serves reads, Vault stays behind it for anything Postgres misses, and new writes land in the journal.
4. **Retire Vault reads.** Set `backends = ["postgres"]`.

You can also shadow-write before step 3: `writer = "postgres"` while `backends` is still `["vault"]` sends writes where reads cannot yet see them. NICo allows this and logs a warning; it is useful on purpose (confirm writes land before reads trust Postgres) and surprising by accident.

Two caveats before writes move off Vault:

- Services with their own read chains (`bmc-proxy`, `dsx-exchange-consumer`) do not see what `nico-api` writes to Postgres. Point them at the same backend, or feed them another way, before the credentials they read change.
- During a rolling upgrade, replicas still on the old config keep writing to their own writer. Keep autonomous credential writers (site-explorer credential rotation) disabled until the whole fleet runs one config.

## Rotating and Retiring Keys

Rotation moves new writes immediately and existing entries on your schedule:

1. **Route to the new key.** Add the new KEK to the active provider (every routed KEK must live there) and point the relevant `[secrets.routing]` entries at it. New writes wrap with it from the next boot; existing entries stay readable under the KEKs they recorded.
2. **Re-wrap existing entries.** Run the walk after rotating:

   ```bash
   nico-admin-cli secrets re-wrap
   ```

   The report counts `re_wrapped`, `already_current`, and `stale_remaining`. Only the DEK wrapping is redone (credential ciphertext is untouched), batches commit independently, and an advisory lock keeps it to one walk at a time, so the command is safe to re-run and resumes where it left off. `--batch-size` sets the rows scanned per batch; a smaller batch lightens the load on an external KMS.

3. **Retire the old key.** `stale_remaining` counts entries wrapped by KEKs that no routing entry references. To retire a KEK: remove it from every routing entry, run `secrets re-wrap` again, and delete the key from its provider only after `stale_remaining` reports 0.
