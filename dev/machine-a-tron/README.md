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

## High Level Code Organization
In order to separate work and hopefully avoid bottlenecks, the code runs different systems in tasks using channels for communication between them.
The following are broken into tasks:
* dhcp_relay - a service that tries to simulate a dhcp relay working on behalf of a machine.  The API sees the request as if it was sent from a relay
and responses accordingly.  The API requires DHCP reqeusts come from a relay and I had trouble getting the actual relay in the dev environment
to work correctly.  Requests are made through the client object and passed a one-shot channel for the response (avoiding a lookup to find the machine for a response).
* tui - a service that handles the UI (when enabled). It simply handles user input (up and down arrows, esc, and q only) as well as receives status updates for display.
* machine-a-tron - the application level that starts all the services and waits for the UI to tell it to stop.
* host_machine - each host gets a task that runs through states and making API requests.  periodically sends status updates to the UI and runs the DPU states owned by the host.
* bmc - runs a bmc-mock that responds to redfish calls using templates in the configured directory

