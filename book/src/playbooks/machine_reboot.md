# Rebooting a machine

This page describes how to reboot a Forge managed Machine (managed host or DPU)
in any potential state of its lifecycle.

## Important note

*This this is not a facing site-provider or tenant facing workflow.
Rebooting a machine while it is in-use for a tenant can have unexpected
side effects. If a tenant requires a reboot, they should use the
`InvokeInstancePower` request - which is properly integrated into the
instance lifecycle.**

## Reboot Steps

The following steps can be used to reboot a machine:

### 1. Obtain access to `carbide-admin-cli`

See [carbide-admin-cli access on a Forge cluster](forge_admin_cli.md).

### 2. Execute the `carbide-admin-cli machine reboot` command

`carbide-admin-cli machine reboot` can be used to restart a machine.
It always will require the machine's BMC IP and port to be specified.

BMC credentials can either be explicitely passed, or the `--machine-id` parameter
can be used to let the forge site-controller read the last known credentials
for the machine.

Rebooting a machine will also always reset its boot order. The machine
will PXE boot, and thereby will be able to retrieve new boot instructions from
the Forge site controller.

**Example:**

```
/opt/carbide/carbide-admin-cli -c https://127.0.0.1:1079 machine reboot --address 123.123.123.123 --port 9999 --machine-id="60cef902-9779-4666-8362-c9bb4b37184f"
```

or using username and password:

```
/opt/carbide/carbide-admin-cli -c https://127.0.0.1:1079 machine reboot --address 123.123.123.123 --port 9999 --username myhost --password mypassword
```
