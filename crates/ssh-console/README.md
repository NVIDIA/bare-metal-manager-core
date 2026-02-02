# SSH Console

An SSH server that acts as a proxy to BMC (Baseboard Management Controller) serial consoles, and logs their output. It
supports multiple BMC vendors (Dell, Lenovo, HPE, NVIDIA) and handles authentication through either OpenSSH certificates
or public key validation via a carbide-api.

This is a rust reimplementation of the old [ssh-console](https://gitlab-master.nvidia.com/nvmetal/ssh-console/),
focusing on simplicity, security, and re-using existing carbide libraries whenever possible.

It is part of the carbide repo so that we can take advantage of the `rpc` crate and get an instance of `ForgeApiClient`
without needing to publish a crate anywhere.

# Code organization

High-level module overview:

- [`ssh_server`](src/ssh_server.rs): Responsible for running the SSH server itself
- [`frontend`](src/frontend.rs): Handles SSH client connections and authentication
- [`bmc::client_pool`](src/bmc/client_pool.rs): Queries carbide-api for what BMC's are available and spawns clients for
  each one, making them available for frontends
- [`bmc::client`](src/bmc/client.rs): Maintains a connection to a given BMC, reconnecting if it fails
- [`bmc::connection`](src/bmc/connection.rs): Types for BMC connections, and looking them up from carbide-api
- [`bmc::connection_impl`](src/bmc/connection_impl/mod.rs): Manages individual connections to BMC devices and serial
  console activation
- [`bmc::message_proxy`](src/bmc/message_proxy.rs): Logic for proxying messages from the SSH frontend to the BMC and
  back
- [`bmc::vendor`](src/bmc/vendor.rs): Vendor-specific logic including escape character prevention and BMC prompt
  detection
- [`config`](src/config.rs): Configuration management with TOML file support
- [`console_logger`](src/console_logger.rs): Write output from BMC's to log files
- [`metrics`](src/metrics.rs): Launches the metrics server
- [`shutdown_handle`](src/shutdown_handle.rs): Utility for easily shutting down and waiting on background tasks

## Code notes

### Concurrency/Background work

Most of the code in this crate has a pattern of:

- Spawn work via a `spawn()` function at the top of the module
- Do prep work in the foreground inside `spawn()`, checking preconditions and returning errors early
- Once prep work is done, do background work in a `tokio::spawn` background task
- Return a `ShutdownHandle` implementation that will cause the work to be shutdown when dropped.

The actual shutdown logic uses a tokio oneshot channel, but this is opaque to the caller. Callers can either let the
handle drop to shut the work down, or call `.shutdown_and_wait()` to shut it down manually and wait for it to finish.

This allows simple concurrency of various tasks, while also using RAII to enforce that any errors don't result in
orphaned tasks running in the background.

## TODO (roughly in order)

- [x] Deploy in dev environments as a separate endpoint from the old ssh-console
- [x] Support IMPI-based connections (currently only works with SSH'able BMC's)
- [x] Implement metrics similarly to legacy SSH console
- [x] Better architecture docs/diagram in this README file
- [ ] (Forge UI) Deploy to production environments, offer up the new ssh-console URL to users as a beta URL to use
- [ ] Decommission old ssh-console once we're satisfied/confident

## Testing

You can test this against a running machine-a-tron cluster by configuring the cluster's mat.toml with:

```
mock_bmc_ssh_server = true
use_single_bmc_mock = false
interface = "lo"
```

which will launch a mock BMC server for each mocked machine. Then this example config should get you started:

```
## What address to listen on.
listen_address = "[::]:3222"

## Address for carbide-api
carbide_url = "https://carbide-api.forge"

## Path to root CA cert for carbide-api
forge_root_ca_path = "/tmp/localdev-certs/ca.crt"

## Client cert path to communicate with carbide-api
client_cert_path = "/tmp/localdev-certs/tls.crt"

## Client key path to communicate with carbide-api
client_key_path = "/tmp/localdev-certs/tls.key"

## Path to the SSH host key path.
host_key = "ssh-console/tests/fixtures/ssh_host_ed25519_key"

## Ports to use when connecting to BMC's
override_bmc_ssh_port = 2222
```

And running with:

```
cargo run -p ssh-console -- -c path/to/config.toml
```

You can also test standalone to a real BMC, by starting a SSH socks proxy to the BMC you want to connect to, e.g.

```
ssh -fNL8022:10.180.247.201:22 renojump
```

and specifying how to to connect to in the config file:

```
[[bmcs]]
# machine_id doesn't matter here, just make sure to use the same string as the username in testing, e.g.
# `ssh -p 3222 fm100htasujpl2icpvjedluh5qjlmba1v6ln075me7rvtdiqsfht08rrkjg@localhost`
machine_id = "fm100htasujpl2icpvjedluh5qjlmba1v6ln075me7rvtdiqsfht08rrkjg"
# ditto instance_id, set it to whatever, just make sure to use this id when ssh'ing, e.g.
# `ssh -p 3222 d40ad750-b925-4b34-b25a-d7f94458cc9e@localhost`
instance_id = "d40ad750-b925-4b34-b25a-d7f94458cc9e"

# ip and port of the SOCKS proxy
ip = "127.0.0.1"
port = 8022

# Valid: "dell", "hpe", "lenovo", "dpu", "nvidia_viking". Affects how BMC escape characters are interpreted, and
# how the serial console is activated.
bmc_vendor = "dell"

user = "root"
password = "get_me_from_vault"
```

## Integration tests

Integration tests are in the `tests` directory, and need the `REPO_ROOT` env var to be set to run. You can run with:

```
REPO_ROOT="$(pwd)" cargo test -p ssh-console --test main
```

## Fuzz tests

There are fuzz tests for the SSH escape character handling, which you can run with:

```
rustup toolchain install nightly
rustup component add llvm-tools-preview --toolchain nightly
cargo +nightly install cargo-fuzz
cargo +nightly fuzz run ssh_console_escape_filter
```

The fuzz tests run basically forever, so when you are satisfied they have not uncovered issues, simply ctrl+c.
