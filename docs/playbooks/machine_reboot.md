# Rebooting a machine

This page describes how to reboot a machine managed by NVIDIA Infra Controller (NICo) (i.e. a managed host or DPU)
in any potential state of its lifecycle.

## Important note

*This is not a site-provider or tenant facing workflow.
Rebooting a machine while it is in-use for a tenant can have unexpected
side effects. If a tenant requires a reboot, they should use the
`InvokeInstancePower` request - which is properly integrated into the
instance lifecycle.**

## Reboot Steps

The following steps can be used to reboot a machine:

### 1. Obtain access to `nicocli`

Configure `nicocli` for the target REST API. The caller's organization must have an Infrastructure Provider that owns the Site containing the Machine, and the caller must have the `PROVIDER_ADMIN` role.

### 2. Execute the Machine power control operation

Use `GracefulRestart` when the operating system can shut down cleanly. Use `ForceRestart` only when a graceful restart is not possible.

```bash
nicocli machine power-control-machine machine-power-control-machine \
  --action GracefulRestart \
  <machine-id>
```

If the Machine has an attached Instance, acknowledge the workload disruption explicitly:

```bash
nicocli machine power-control-machine machine-power-control-machine \
  --action GracefulRestart \
  --acknowledge-attached-instance true \
  <machine-id>
```

A successful request returns HTTP 202. Retrieve the Machine afterward with `nicocli machine get <machine-id>` and confirm that it returns to the expected lifecycle state.
