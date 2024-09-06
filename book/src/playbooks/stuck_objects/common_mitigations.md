## Stuck Object Mitigations

Unfortunately there does not exist a common mitigation to all kinds of problems
that show up. Many issues will require a unique mitigation that is tailored
to the root cause of the object being stuck.

Therefore operators are required to understand the requirements for state transitions
and how Forge system components work together. The previous sections of this
runbook should help with this.

However there exists a few common requirements for state transitions, and repeated
reasons on why those might be failing. This section provides an overview for those.

### 4.1 Common requirements and failures for `ManagedHost` state transitions

#### 4.1.1 Machine reboots

Various state transitions require a machine (Host or DPU) to be rebooted.
The reboot is indicated by the forge-scout performing a `ForgeAgentControl` call
on startup of the machine.

The following issues might prevent this call from happening:
- The reboot request never succeeds due to the Machine being powered down,
  not reachable via redfish, or due to issues during credential loading.
  These errors should all show up in carbide-api logs.
- The machine reboots, but can either not obtain an IP address via DHCP or
  can not PXE boot. The serial console that is accessible via the BMC of a machine
  or via `forge-ssh-console` can be used to determine whether the Machine booted
  successfully, or whether it bootloops and not obtain an IP or load an image.
  If the boot process does not succeed, check carbide-dhcp and carbide-pxe for
  further logs.
  **TODO: Better runbooks for DHCP failures**
- The machine boots into the discovery image (or BFB for DPUs), but the execution
  inside `forge-scout` will fail. For this case check the carbide-api logs on
  whether scout was able to send a `ReportForgeScoutError` call which indicates
  the source of the problem. If the machine is not able to enumerate
  hardware, or if carbide-api is not accessible to the machine, such an error
  report will not be available. You can however access the host via serial console
  and check the logfile that forge-scout generates (`/var/log/forge/forge-scout.log`)
  in order to further investigate the problem.

#### 4.1.2 Feedback from forge-dpu-agent

Whenever the configuration of a ManagedHost changes (Instance gets created,
Instance gets deleted, Provisioning), Forge requires the `forge-dpu-agent` to
acknowledge that the desired DPU configuration is applied and that the DPU and
services running on it (like `HBN`) are in a healthy state.

[If the DPU has not recently reported that it is up, healthy and that the latest
desired configuration is applied](https://gitlab-master.nvidia.com/nvmetal/carbide/-/blob/38849aed602a2ab6e19a5315b342db3d4535b143/api/src/state_controller/machine/handler.rs#L104-114),
the state will not be advanced.

If a ManagedHost is stuck due to this check, you can inspect which condition is
not met by inspecting the last report from the DPU via forge-admin-cli.

E.g. in the following report
```
/opt/carbide/forge-admin-cli managed-host show --host fm100pskla0ihp0pn4tv7v1js2k2mo37sl0jjr8141okqg8pjpdpfihaa80
Hostname    : oven-bakerloo
State       : Host/WaitingForDiscovery

Host:
----------------------------------------
  ID                 : fm100pskla0ihp0pn4tv7v1js2k2mo37sl0jjr8141okqg8pjpdpfihaa80
  ...
  Network unhealthy  : ipv4_unicast failed peers is 1 should be 0

DPU:
----------------------------------------
  ID                 : fm100dskla0ihp0pn4tv7v1js2k2mo37sl0jjr8141okqg8pjpdpfihaa80
  Last reboot        : 2023-09-11 21:23:38.296311 UTC
  Last seen          : 2023-09-13 22:35:38.936301376 UTC
```

- "Network is healthy" will indicate whether any of the DPUS health-check failed.
  If a health-check has failed, then the root-caused for the failed health-check
  needs to be remediated.
- "Last seen" indicates whether the DPU (and `forge-dpu-agent`) is up and running.
  If the timestamp is too old, it might indicate the DPU agent has crashed or the
  whole DPU is no longer online. In this case an operator should SSH onto the DPU
  and inspect the state of `forge-dpu-agent`. The dpu agent logs which are locally
  available on the DPU using `journalctl -u forge-dpu-agent.service` can help with
  this investigation. If forge-dpu-agent is not even started,
  then it needs to be started (`systemctl enable forge-dpu-agent.service`).
  This should however never be necessary, since the agent gets restarted on all
  crashes.

An alternative tool that can be used to inspect the state of all DPUs is the
`forge-admin-cli machine network status` command, which lists the latest reported
states of all DPUs within a Forge Site.

The following example report shows a DPU `fm100dskla0ihp0pn4tv7v1js2k2mo37sl0jjr8141okqg8pjpdpfihaa80`
whose `BgpStats` health-check has failed:
```
/opt/carbide/forge-admin-cli machine network status
+--------------------------------+-------------------------------------------------------------+------------------------+-------------+-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+---------------+--------------------------------------------+
| Observed at                    | DPU machine ID                                              | Network config version | Is healthy? | Checks passed                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     | Checks failed | First failure                              |
+--------------------------------+-------------------------------------------------------------+------------------------+-------------+-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+---------------+--------------------------------------------+
| 2023-09-13T22:38:53.223285483Z | fm100dskla0ihp0pn4tv7v1js2k2mo37sl0jjr8141okqg8pjpdpfihaa80 | V2-T1694466270293052   | false       | ContainerExists,SupervisorctlStatus,ServiceRunning(frr),ServiceRunning(nl2doca),ServiceRunning(rsyslog),DhcpRelay,Ifreload,BgpDaemonEnabled,FileExists(/var/lib/hbn/etc/frr/frr.conf),FileIsValid(/var/lib/hbn/etc/frr/frr.conf),FileExists(/var/lib/hbn/etc/network/interfaces),FileIsValid(/var/lib/hbn/etc/network/interfaces),FileExists(/var/lib/hbn/etc/supervisor/conf.d/default-isc-dhcp-relay.conf),FileIsValid(/var/lib/hbn/etc/supervisor/conf.d/default-isc-dhcp-relay.conf),FileExists(/var/lib/hbn/etc/frr/daemons),FileIsValid(/var/lib/hbn/etc/frr/daemons)                                       | BgpStats      | ipv4_unicast failed peers is 1 should be 0 |
+--------------------------------+-------------------------------------------------------------+------------------------+-------------+-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+---------------+--------------------------------------------+
```

## Optional Step 5: Mitigation by deleting the object using the Forge Web UI or API

In order to fix the problem of instance or subnet stuck in provisioning,
it often seems appealing to just delete the object and retry.

**This mitigation will however only work if the object has not even
been created on the Forge Site and if the source of the creation problem is
within the scope of the Forge Cloud Backend.**

If the object was already created on the site and is stuck in a certain 
provisioning state there, then the deletion attempt will not help getting
the object unstuck. The lifecycle of any object is fully linear
with no shortcuts. If the object isn't getting `Ready` it will also never
be deleted. The object lifecycle is implemented this way in Forge in order to
avoid any important object creation or deletion steps accidentally being skipped due to
skipping states.

**Due to this reason, it is usually not helpful to initiate deletion of
objects stuck in Provisioning. Instead of this, the reason for an object 
stuck in provisioning should be inspected and the underlying issue being 
resolved.**