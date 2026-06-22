# DPU Provisioning Failures

Use this playbook when a DPU is stuck during discovery, initialization,
reprovisioning, secure boot setup, or network configuration.

## Where Failures Appear

DPU provisioning issues usually show up in two places:

| Layer | Examples |
|---|---|
| NICo state machine | `DpuDiscoveringState`, `DPUInit`, `DPUReprovision`, `Assigned/DPUReprovision`. |
| DPF operator resources | DPU device, provisioning, secure boot, and service state. |

Start with NICo state. Move to DPF resources when NICo is waiting on DPF.

```bash
nico-admin-cli managed-host show <host-machine-id>
nico-admin-cli -f json machine show <host-machine-id>
```

## Install Path

Know which install path is active before debugging.

| Path | How it works | Common blockers |
|---|---|---|
| BFB install over Redfish | NICo or DPF instructs the DPU BMC to install a BFB. | Redfish connectivity, BMC credentials, BFB availability. |
| UEFI HTTP boot | DPU boots over HTTP through `nico-pxe`. | DHCP, HTTP boot URL, TLS root CA, boot order, DPU NIC path. |
| Reprovision | Existing DPU is updated or reinstalled. | User approval, assigned instance state, BFB version, DPF status. |

## Common States

### `DpuDiscoveringState`

NICo is discovering the DPU and preparing it for provisioning.

Check:

- DPU BMC reachability.
- Redfish credentials and Vault access.
- Site Explorer reports for the DPU BMC.
- DPF device status if DPF owns the next step.

### `DPUInit`

NICo is installing or bringing up the DPU OS and services.

Check:

- DPU BMC power and console.
- DPU install method: BFB over Redfish or UEFI HTTP boot.
- `nico-pxe` logs for HTTP boot requests.
- DPF operator status.
- `nico-dpu-agent` startup logs once the OS boots.

### `WaitingForNetworkConfig`

NICo blocks state advancement until the DPU agent reports:

1. It is alive.
2. It applied the latest desired network config version.
3. Its DPU network health is acceptable.

```bash
nico-admin-cli managed-host show <host-machine-id>
nico-admin-cli machine network status
nico-admin-cli machine health-report show <dpu-machine-id>
```

If `Last seen` is stale or `HeartbeatTimeout` is present, inspect the DPU
directly:

```bash
journalctl -u nico-dpu-agent.service -e --no-pager
```

### `DPUReprovision`

Reprovisioning may require approval when a host is assigned to an instance.

```bash
nico-admin-cli dpu reprovision list
nico-admin-cli dpu reprovision restart --id <host-machine-id>
```

If the host is assigned, confirm the tenant or user approval path before
forcing disruptive actions.

## Health Probes

Common DPU probe alerts:

| Probe | Meaning | First checks |
|---|---|---|
| `HeartbeatTimeout` | NICo has not received recent DPU agent health. | DPU booted, agent running, DPU can reach `nico-api`. |
| `BgpStats` | BGP peering is not healthy. | HBN container, FRR/BGP status, TOR or route-server reachability. |
| `ServiceRunning` | Required DPU service is down. | `crictl ps`, systemd status, HBN logs. |
| `DhcpRelay` / `DhcpServer` | Host-facing DHCP path is broken. | DPU agent logs, HBN, DHCP relay/server config. |

## DPU Console and Logs

If SSH to the DPU works:

```bash
ssh <dpu-oob-ip>
journalctl -u nico-dpu-agent.service -e --no-pager
```

If SSH fails, use DPU BMC or rshim access and check whether the DPU OS booted.

Useful on-DPU checks:

```bash
systemctl status nico-dpu-agent.service
journalctl -u nico-dpu-agent.service -e --no-pager
sudo crictl ps
sudo crictl exec -ti $(sudo crictl ps | grep doca-hbn | awk '{print $1}') vtysh -c 'show bgp summary'
```

## Mitigations

Use the least disruptive mitigation that addresses the root cause.

| Situation | Mitigation |
|---|---|
| DPU agent is stopped | `systemctl restart nico-dpu-agent.service` |
| Unit files changed | `systemctl daemon-reload && systemctl restart nico-dpu-agent.service` |
| DPU is unresponsive | Power cycle host only after confirming tenant or operator impact. |
| Reprovision stuck | `nico-admin-cli dpu reprovision restart --id <host-machine-id>` |
| False health blocker | Add a temporary override only with incident context and remove it after recovery. |
