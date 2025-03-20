# Local API server

This contains configs and scripts for running an *additional* API server,
connected to a database that is already running in a local kubernetes cluster
(e.g. via k3s deployed from the `forged` repo.)

This additional API server will not run any state controllers, site-explorer,
etc, and will not have working vault authentication. It will listen on
plaintext HTTP/1.1 (upgradable to HTTP2) requests to avoid needing a working
TLS setup.

You still need a working kubernetes environment that has a working postgres
server deployed to it, and currently this only works on Linux (macOS can't
compile carbide-api due to not being able to build tss-eapi.)

## Running from your terminal

Run `dev/local-api-server/run.sh` from the root of the repo.

## Running from an IDE, etc

You may, for example, want to configure your IDE with the env vars and run command.

For the env vars, run `dev/local-api-server/eval_me_for_env_vars.sh`, which will dump them to stdout.

The cargo command to run the local API server becomes:

```
cargo run -p carbide-api -- run --config-path dev/local-api-server/carbide-api-config.toml
```
