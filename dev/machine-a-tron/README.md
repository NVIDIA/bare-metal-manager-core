# Machine-A-Tron
A rust tool that uses the api client to simulate machines in the forge development environment.

The purpose of this tool is similar to the bootstrap scripts in `dev/bin` to build machines in the local-dev environment.  I will generate machine information from the files in the template directory and fill in the dynamic data as needed (product serial, mac address, etc).  this allows it to create multiple managed hosts.  I will stay running and periodically report health network observations.

## Usage
```
target/debug/machine-a-tron -h
Usage: machine-a-tron [OPTIONS] --relay-address <RELAY_ADDRESS> <NUM_HOSTS> [CARBIDE_API]

Arguments:
  <NUM_HOSTS>    The number of host machines to create
  [CARBIDE_API]  the api url

Options:
      --forge-root-ca-path <FORGE_ROOT_CA_PATH>
          Default to FORGE_ROOT_CA_PATH environment variable or $HOME/.config/carbide_api_cli.json file. [env: FORGE_ROOT_CA_PATH=]
      --client-cert-path <CLIENT_CERT_PATH>
          Default to CLIENT_CERT_PATH environment variable or $HOME/.config/carbide_api_cli.json file. [env: CLIENT_CERT_PATH=]
      --client-key-path <CLIENT_KEY_PATH>
          Default to CLIENT_KEY_PATH environment variable or $HOME/.config/carbide_api_cli.json file. [env: CLIENT_KEY_PATH=]
      --template-dir <TEMPLATE_DIR>
          directory containing template files.
      --relay-address <RELAY_ADDRESS>
          relay address for env.
  -h, --help
          Print help

```

## OMG Panics Everywhere

Yes, this uses `unwrap()` and `expect()` all over the place.  As a result is a happy path only kind of tool.  This is on my list of things to fix.