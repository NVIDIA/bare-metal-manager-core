# carbide-ipmitool

Pure-Rust IPMI v1.5/v2.0 client library and CLI, replacing the C
`ipmitool` binary. Supports both `-I lan` (IPMI v1.5) and `-I lanplus`
(IPMI v2.0 RMCP+). Eliminates the OpenSSL/C dependency for BMC
communication.

## C implementation

- [ipmitool](https://github.com/ipmitool/ipmitool)


## Build and test
For ad-hoc debugging,create a temporary Rust example in 'examples/' and run it
with `cargo run --example <name>`.  Remove the example after user

Use `tmp/` (create-local) for intermediate files and comparison artifacts, not `/tmp`.
This keeps outputs discoverable and project scoped.  THe `tmp/` directory is gitignored.


## Crate layout

```
crates/ipmitool/
├── Cargo.toml          # name = "carbide-ipmitool", [lib] name = "ipmitool"
├── src/
│   ├── lib.rs          # Re-exports, ConnectionConfig, IpmiClient (stub)
│   ├── main.rs         # CLI binary (clap + color-eyre)
│   ├── error.rs        # IpmitoolError (thiserror)
│   ├── cli/            # One file per command group — clap derive + output formatting
│   ├── cmd/            # One file per command group — IPMI command logic
│   ├── crypto/         # HMAC-SHA1/SHA256/MD5, AES-CBC-128, key derivation
│   ├── transport/      # IpmiTransport trait, Transport enum, LanTransport, LanplusTransport, MockTransport
│   │   ├── lan/        # IPMI v1.5 LAN: packet build/parse, MD5 auth, session state
│   │   └── lanplus/    # RMCP+ packet build/parse, RAKP handshake, session state
│   └── types/          # NetFn, CompletionCode, IpmiRequest/Response, sensor/FRU/SEL types
```

## Key commands

```sh
cargo build -p carbide-ipmitool
cargo test -p carbide-ipmitool
cargo clippy -p carbide-ipmitool

# Against a real BMC (v2.0 RMCP+):
cargo run -p carbide-ipmitool -- -I lanplus -H <bmc-ip> -U <user> -P <pass> chassis power status
cargo run -p carbide-ipmitool -- -I lanplus -H <bmc-ip> -U <user> -P <pass> mc info

# Against a v1.5-only BMC:
cargo run -p carbide-ipmitool -- -I lan -H <bmc-ip> -U <user> -P <pass> chassis power status
```
## Tricky areas
These are areas where the implementation is non-obvious or where bugs are likely
to hide.

### SOL `select!` loop borrow dance

The interactive SOL session in `transport/lanplus/sol.rs` uses a
`tokio::select!` loop with two branches (BMC recv + stdin read). To
satisfy the borrow checker, all session crypto parameters (AES key,
K1, managed session ID, integrity algorithm, auth code length) are
extracted into local variables *before* the loop. Inside the loop,
`self.session` is only touched in branch bodies (for `next_seq()`),
which is safe because `select!` runs one branch at a time. The
`UdpSocket` is borrowed as a shared reference (`&self.socket`) since
`recv`/`send` take `&self`. Do not refactor to capture `&mut self` in
the futures themselves — it will fail to compile.

## Issue tracking
Issues live in `issues/`, one file per issue. Filename format:
`<uuid>-short-description.md` (use `$(uuidgen)`). Some older issues
use numeric prefixes instead. Check existing issues before filing to
avoid duplicates.

Issues caused by bugs in the upstream ipmitool project live in 
`upstream-issues/` instead. These are tracked separately since 
they cannot be fixed in this project.

Each issue file should include:
- **Symptom**: what's wrong or missing
- **Root cause**: why it happens (if known)
- **Affected files**: which source files are involved
- **Reproduction**: commands or test case to reproduce
- **Suggested fix**: approach sketch

## Changelog

This project keeps a changelog following
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/). When making
user-facing changes, add an entry to the `[Unreleased]` section of
`CHANGELOG.md` under the appropriate category (Added, Changed,
Deprecated, Removed, Fixed, Security). The `[Unreleased]` section
always retains headings for all six categories, even when empty. Omit
empty categories only in released version sections.

Every entry must earn its place: the changelog is for users of the
library and binary, not for contributors. Internal changes (test
infrastructure, CI, issue tracking, code formatting, dev-only
scripts) do not belong. When in doubt, ask: "would a user deciding
whether to upgrade care about this?"

Write entries in imperative mood ("Validate ...", "Reject ..."), not
declarative ("Validates ...", "now rejects ..."). Describe the
user-visible effect, not the implementation technique — e.g., "Render
all errors with colored, annotated source excerpts" rather than "Use
miette diagnostic rendering for all error output".

Categorize by what the change *is*, not what code it touches: new
capabilities (including new validations and warnings) go in **Added**,
changes to existing behavior in **Changed**, and actual bug
corrections in **Fixed**.

Entries need not map one-to-one to commits: several commits may be
unified under one entry when they contribute to a single user-visible
change. Each entry references a primary commit by its short hash at
the end of the line (GitHub auto-links these).

## Protocol details to keep in mind

- All multi-byte fields are **little-endian**.
- AES-CBC-128 uses **IPMI custom padding** (pad bytes 1,2,3..N, then
  pad-length byte), NOT PKCS#7. See `crypto/aes_cbc.rs`.
- Session sequence numbers **skip zero** when incrementing.
- HMAC for integrity covers session header through
  padding+pad_len+next_header (0x07).
- Cipher suite 17: HMAC-SHA256 auth + HMAC-SHA256-128 integrity
  (truncated to 16 bytes) + AES-CBC-128.

## Implementation status

Phases 1-6.5 are complete on the `vibe_ipmitool` branch (182 tests).

| Phase | Status | What |
|-------|--------|------|
| 1 | Done | Types, error, crypto, packet parsing |
| 2 | Done | RAKP handshake, LanplusTransport, session state machine |
| 3 | Done | Core commands (chassis, mc, raw) + CLI binary |
| 4 | Done | Data commands (sdr, sel, fru, sensor) |
| 5 | Done | User and channel management |
| 6 | Done | SOL activation/config |
| 6.5 | Done | Interactive SOL terminal (bidirectional I/O, escape handling) |
| 6.6 | Done | IPMI v1.5 LAN transport (`-I lan`) with MD5/None auth, `Transport` enum dispatch |
| 7 | **Blocked** | Replace shell-out in `crates/api/src/ipmitool.rs` — **do not start until tested against a real BMC** |

## Testing

- **MockTransport** (`transport/mock.rs`): HashMap-keyed canned
  responses for single-request command tests.
- **QueueMockTransport** (`transport/mock.rs`): FIFO queue for
  multi-response iteration tests (SDR/SEL/FRU sequences).
- Tests are inline `#[cfg(test)]` modules in each source file.
- No real-host tests have been run yet. That is the next milestone.

## Important constraints

- `IpmiClient` in `lib.rs` is a stub — the working path is
  `LanplusTransport::connect(config)` then calling `cmd::*` functions
  directly. Fleshing out `IpmiClient` as a high-level wrapper is a
  future task.
- The interactive SOL terminal does not yet implement keep-alive
  pings, packet retransmit on NACK/timeout, or `~R` reconnect.
  `cmd/sol.rs` covers the IPMI command layer; the interactive session
  lives in `transport/lanplus/sol.rs`.
- The `md-5` crate (not `md5`) is the digest-compatible HMAC-MD5
  implementation. The workspace `md5 = "0.7"` is a different,
  incompatible crate used elsewhere.
- IPMI v1.5 LAN auth types MD2 (`0x01`) and straight password
  (`0x04`) are intentionally deferred — MD2 is obsolete and straight
  password is insecure. Only MD5 and None are implemented.
- SOL interactive sessions are lanplus-only; attempting `sol activate`
  with `-I lan` produces a clear error message.
