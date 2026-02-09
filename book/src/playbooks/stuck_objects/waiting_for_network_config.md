# `WaitingForNetworkConfig` and DPU health

Whenever the configuration of a ManagedHost changes (Instance gets created,
Instance gets deleted, Provisioning), Forge requires the `forge-dpu-agent` to
acknowledge that the desired DPU configuration is applied and that the DPU and
services running on it (like `HBN`) are in a healthy state.

This feedback mechanism works in the following fashion:
1. `forge-dpu-agent` periodically calls `GetManagedHostNetworkConfig`. It thereby
   obtains the latest configuration for all interfaces, including the configuration
   which states whether the Host should get attached to an admin or tenant network.
   The configuration includes Version numbers, which increase whenever the
   configuration changes.
2. `forge-dpu-agent` reports the version numbers of the currently applied
   configurations back to Carbide using the `RecordDpuNetworkStatus` API.
   This report also includes the DPUs health in the form of a `HealthReport`.

[If the DPU has not recently reported that it is up, healthy and that the latest
desired configuration is applied](https://gitlab-master.nvidia.com/nvmetal/carbide/-/blob/38849aed602a2ab6e19a5315b342db3d4535b143/api/src/state_controller/machine/handler.rs#L104-114),
the state will not be advanced.

If a ManagedHost is stuck due to this check, you can inspect which condition is
not met by inspecting the last report from the Host and DPUs
- via carbide-admin-cli:
  - ```
    carbide-admin-cli managed-host show fm100psa0aqpqvll7vi4jfrvtqv058mo8ifb0vtg761j06sqhq466b0slmg
    ```
  - ```
    carbide-admin-cli machine show fm100psa0aqpqvll7vi4jfrvtqv058mo8ifb0vtg761j06sqhq466b0slmg
    ```
  - ```
    carbide-admin-cli machine show fm100dsa0aqpqvll7vi4jfrvtqv058mo8ifb0vtg761j06sqhq466b0slmg
    ```
  - ```
    carbide-admin-cli machine network status
    ```
- via Forge Admin Web UI:
  - [https://api-pdx01.frg.nvidia.com/admin/managed-host/fm100psa0aqpqvll7vi4jfrvtqv058mo8ifb0vtg761j06sqhq466b0slmg](https://api-pdx01.frg.nvidia.com/admin/managed-host/fm100psa0aqpqvll7vi4jfrvtqv058mo8ifb0vtg761j06sqhq466b0slmg)
  - [https://api-pdx01.frg.nvidia.com/admin/machine/fm100psa0aqpqvll7vi4jfrvtqv058mo8ifb0vtg761j06sqhq466b0slmg](https://api-pdx01.frg.nvidia.com/admin/machine/fm100psa0aqpqvll7vi4jfrvtqv058mo8ifb0vtg761j06sqhq466b0slmg)
  - [https://api-pdx01.frg.nvidia.com/admin/machine/fm100dsa0aqpqvll7vi4jfrvtqv058mo8ifb0vtg761j06sqhq466b0slmg](https://api-pdx01.frg.nvidia.com/admin/machine/fm100dsa0aqpqvll7vi4jfrvtqv058mo8ifb0vtg761j06sqhq466b0slmg)

E.g. in the following report
```
/opt/carbide/carbide-admin-cli managed-host show fm100psa0aqpqvll7vi4jfrvtqv058mo8ifb0vtg761j06sqhq466b0slmg
Hostname    : 10-217-18-95
State       : DPUInitializing/WaitingForNetworkConfig
    Time in State : 296 days and 29 minutes
    State SLA     : 30 minutes
    In State > SLA: true
    Reason        : The object is in the state for longer than defined by the SLA. Handler outcome: Wait("Waiting for DPU agent to apply network config and report healthy network for DPU fm100dsa0aqpqvll7vi4jfrvtqv058mo8ifb0vtg761j06sqhq466b0slmg")

Host:
----------------------------------------
  ID                    : fm100psa0aqpqvll7vi4jfrvtqv058mo8ifb0vtg761j06sqhq466b0slmg
  Memory                : Unknown
  Admin IP              : 10.217.18.95
  Admin MAC             : B8:3F:D2:B7:70:64
  Health
    Probe Alerts        : HeartbeatTimeout [Target: forge-dpu-agent]:
    Overrides
  BMC
    Version             : Unknown
    Firmware Version    : Unknown
    IP                  : Unknown
    MAC                 : Unknown

DPU0:
----------------------------------------
  ID                    : fm100dsa0aqpqvll7vi4jfrvtqv058mo8ifb0vtg761j06sqhq466b0slmg
  State                 : DPUInitializing/WaitingForNetworkConfig
  Primary               : true
  Failure details       : Unknown
  Last reboot           : 2023-12-13 16:38:08.180734 UTC
  Last reboot requested : Unknown/
  Last seen             : 2023-12-13 17:24:15.454965 UTC
  Serial Number         : MT2244XZ022R
  BIOS Version          : BlueField:3.9.3-7-g8f2d8ca
  Admin IP              : 10.217.134.233
  Admin MAC             : B8:3F:D2:B7:70:72
  BMC
    Version             : 1
    Firmware Version    : 2.08
    IP                  : 10.217.134.234
    MAC                 : B8:3F:D2:B7:70:66
  Health
    Probe Alerts        : HeartbeatTimeout [Target: forge-dpu-agent]: No health data was received from DPU
```

- The `Health` field indicates whether any of the health checks failed. In this case we can see an alert of the `HeartbeatTimeout` probe - with target `forge-dpu-agent`. That indicates no
  `HealthReport` had been received from `forge-dpu-agent` via a `RecordDpuNetworkStatus`
  API call for a certain amount of time.
- The aggregate `Health` of a Host is the aggregation of Health states from
  monitoring by `forge-dpu-agent`, out of band BMC monitoring (`hardware-health`),
  and the results of validation tests. If the health check failure also shows up
  in the `Health` field of the DPU, then the failure is related to the DPU,
  and/or has been reported by `forge-dpu-agent`.
  If a health-check has failed, then the root-caused for the failed health-check
  needs to be remediated.
- "Last seen" indicates whether the DPU (and `forge-dpu-agent`) is up and running.
  If the timestamp is too old, it might indicate the DPU agent has crashed or the
  whole DPU is no longer online. In such a case a `HeartbeatTimeout` alert on the
  DPU and Host would be raised too.

The network status details show:
```
/opt/carbide/carbide-admin-cli machine network status
+-------------------------+-------------------------------------------------------------+------------------------+----------+--------------------------------------------+---------------------------------+
| Observed at             | DPU machine ID                                              | Network config version | Healthy? | Health Probe Alerts                        | Agent version                   |
+=========================+=============================================================+========================+==========+============================================+=================================+
| 2023-12-13 17:24:15.454 | fm100dsa0aqpqvll7vi4jfrvtqv058mo8ifb0vtg761j06sqhq466b0slmg | V2-T1702485344893918   | false    | HeartbeatTimeout [Target: forge-dpu-agent] | v2023.12-rc1-43-g3322d125f      |
+-------------------------+-------------------------------------------------------------+------------------------+----------+--------------------------------------------+---------------------------------+
```

In this case we learn that the DPU was alive before, and acknowledged network config version `V2-T1702485344893918`. This is still the desired network configuration version for
this DPU. The target configuration for a DPU can be found on the `Network Config` block
the DPU page in the admin Web UI: [https://api-pdx01.frg.nvidia.com/admin/machine/fm100dsa0aqpqvll7vi4jfrvtqv058mo8ifb0vtg761j06sqhq466b0slmg](https://api-pdx01.frg.nvidia.com/admin/machine/fm100dsa0aqpqvll7vi4jfrvtqv058mo8ifb0vtg761j06sqhq466b0slmg)

The summary for this example is that the Machine is stuck because the DPU
- is either not healthy at all (e.g. not booted)
- is not running `forge-dpu-agent`
- `forge-dpu-agent` is not reporting back to carbide

## Follow-up investigation steps

### Checking DPU liveliness

Operators can try SSHing to the DPU, using the DPU OOB address that is shown
on ManagedHost pages and DPU details pages.
If SSH fails, the DPU might not be up and running.

If directly SSHing to the DPU does not work, it can be accessed via its BMC
and rshim to investigate its state.

**TODO:** Document the BMC path

### Checking DPU agent logs

In case the DPU is running, `forge-dpu-agent` logs can be inspected in order to
learn why it can not communicate with carbide, or why the configuration application
might have failed. There are various options for this.

#### Checking logs via Grafana & Loki

forge-dpu-agent logs are forwarded via OpenTelemetry to the site controller logging
infrastructure. They can be queried from there via Loki.

Search strings for DPU can be:
```
{systemd_unit="forge-dpu-agent.service", machine_id="fm100ds006eliqt3u4h65ou9ebrqfq9th2jf39qqki68k9ueu2amearv47g"}
{systemd_unit="forge-dpu-agent.service", host_name="10-217-155-135.dev3.frg.nvidia.com"}
```

These can be used in the Grafana Explore Screen, e.g. [like here](https://grafana-dev3.frg.nvidia.com/explore?panes=%7B%22uNJ%22:%7B%22datasource%22:%22P8E80F9AEF21F6940%22,%22queries%22:%5B%7B%22refId%22:%22A%22,%22expr%22:%22%7Bsystemd_unit%3D%5C%22forge-dpu-agent.service%5C%22,%20host_name%3D%5C%2210-217-155-135.dev3.frg.nvidia.com%5C%22%7D%22,%22queryType%22:%22range%22,%22datasource%22:%7B%22type%22:%22loki%22,%22uid%22:%22P8E80F9AEF21F6940%22%7D,%22editorMode%22:%22code%22%7D%5D,%22range%22:%7B%22from%22:%22now-6h%22,%22to%22:%22now%22%7D%7D%7D&schemaVersion=1&orgId=1).

**Note that the query using the MachineId will only work if the DPU once had been fully ingested
and is aware of its Machine ID. Otherwise only searches by `host_name` will work.**

In case the DPU problem affects log forwarding, DPU logs need to be checked
directly on the DPU.

#### Checking logs on the DPU:

The dpu agent logs are stored in the systemd journal on the DPU.
They can be queried using
```
journalctl -u forge-dpu-agent.service -e --no-pager
```

### Checking additional logs

Depending on the problems that are found in dpu-agent logs, it can be useful
to check other logs that are available on the DPU. Examples are
- `nl2doca` logs: `{machine_id="fm100ds02e5g65099ov37rmho1gnge0c99ihdisvluo4fls1ba3br9bksg0", log_file_path="/var/log/doca/hbn/nl2docad.log"}`
- `syslog`: `{machine_id="fm100ds02e5g65099ov37rmho1gnge0c99ihdisvluo4fls1ba3br9bksg0", log_file_path="/var/log/doca/hbn/syslog"}`
- `nvue` logs
- `frr` logs

## Potential Mitigations

### Power Cycling the Host

**⚠️ Note that while a tenant uses a Machine as an instance, powercycling the Host will interrupt
their workloads. Only perform these step if its clear that the Tenant no longer requires the Machine (is stuck in termination), or if the Tenant agrees with this action.**

If the DPU is unresponsive, powering off the Host and back on can help. This will
restart the DPU.

The Host can be powercycled using the Explored-Endpoint view in the Admin Web UI,
e.g. [https://api-dev3.frg.nvidia.com/admin/explored-endpoint/10.217.155.16](https://api-dev3.frg.nvidia.com/admin/explored-endpoint/10.217.155.16).
The DPU Machine details page will link to the explored endpoint by clicking on the DPU BMC IP.

### Restarting forge-dpu-agent

If forge-dpu-agent is not even started, then it needs to be started (`systemctl enable forge-dpu-agent.service`).
This should however never be necessary, since the agent gets restarted on all
crashes.

If `forge-dpu-agent` should just be restarted, use
```
systemctl restart forge-dpu-agent.service
```

### Reloading forge-dpu-agent configurations

In rare situations, it might be useful to restart forge-dpu-agent using latest
dpu-agent systemd config files. To do so:
```
systemctl daemon-reload
systemctl restart forge-dpu-agent.service
```

## Mitigations for specific Health Probe Alerts

### `BgpStats`

The BgpStats health probe indicates that BGP peering with the TOR or route server
is not successful. This might either indicate a link issue or a configuration issue.
The BGP details can be checked on the DPU using
```
sudo crictl exec -ti $(sudo crictl ps |grep doca-hbn |awk '{print $1}') vtysh -c 'show bgp summary'
```

**TODO: Provide more details on the next steps here**

### `ServiceRunning`

Indicates that mandatory DPU services are not running. Next steps in the investigation
can be to check whether the HBN container is running on the DPU (`crictl ps` should
show `doca-hbn` container), and to search for associated logs.

### `DhcpRelay`/`DhcpServer`

Indicates that the DHCP Relay or Server that Forge deploys on the DPU in order
to respond to the DHCP requests from the Host are not running as intended.
In these conditions, the Host would not be able to boot since nothing would respond
to the DHCP request.

Next steps in the investigation would be to check `forge-dpu-agent` logs for details.

### `PostConfigCheckWait`

This alert is only raised for a brief time after each configuration change in order
to wait for the configuration to settle on the DPU. The alert should always settle
down after less than a minute. In case the alert keeps raised, it can indicate
that new configurations are applied in every dpu-agent eventloop iteration. In this
case it would need to be debugged what in the configurations changed, and the
source of the unnecessary configuration changes would need to be fixed.
