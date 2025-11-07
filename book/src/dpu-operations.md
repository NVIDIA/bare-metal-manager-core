# Operating Bluefield/DPU

### Connecting to DPU
The DPU shares a physical 1GB ethernet connection for both BMC and OOB access.
This one interface has two different MAC addresses. So, while the physical
connection is shared the OOB and BMC have unique IP addresses.

The BMC OS is a basic `busybox` shell,  so the available commands are limited.
To connect the BMC, ssh to the IP address listed under `DPU BMC IP` address
using credentials in the `DPU BMC Credentials` table above.

To then connect to the 'console' of the DPU you use `microcom` on the
console device

```
microcom /dev/rshim0/console

Press enter to bring up login prompt.

use the login credentials in the DPU OOB column to connect

ctrl-x will break out of the connection
```

Another way (and preferred if the OOB interfaces are provisioned) is to ssh
directly to the IP listed in `DPU OOB IP` and use the credentials in the
`DPU OOB Credentials` column. This bypasses the BMC and connects you directly to
the DPU OS.

#### Updating to the latest BFB on a DPU


Download the latest BFB from artifactory - https://urm.nvidia.com/artifactory/list/sw-mlnx-bluefield-generic/Ubuntu20.04/

In order to upgrade the OS you will need to `scp` the BFB file to a specific directory on the DPU.
`scp DOCA_1.3.0_BSP_3.9.0_Ubuntu_20.04-3.20220315.bfb root@bmc_ip:/dev/rshim0/boot` once the file is copied the DPU reboots and completes the install of the new BFB.

Note you will need to request access to the ` forge-dev-ssh-access` ssh group
in order to login to a jump host.



Recent versions of BFB can also contain firmware updates which can need to be applied using `/opt/mellanox/mlnx-fw-updater/mlnx_fw_updater.pl` after that completes
you must power cycle (not reboot) the server.  For HP the "Cold restart" option in iLO works.

`mlxfwmanager` will tell you the current version of firmware as well as the new version that will become active on power cycle

Open Vswitch is loaded on the DPUs
`ovs-vsctl` show will show which interfaces are the bridge interfaces

From the ArmOS BMC you can instruct the DPU to restart using

`echo "SW_RESET 1" > /dev/rshim0/misc`

The DPU Might require the following udev rules to enable auto-negotiation.  You can look if that is already enable

```
echo 'SUBSYSTEM=="net", ACTION=="add", NAME=="p0", RUN+="/sbin/ethtool -s p0 autoneg on"' >> /etc/udev/rules.d/83-net-speed.rules
echo 'SUBSYSTEM=="net", ACTION=="add", NAME=="p1", RUN+="/sbin/ethtool -s p1 autoneg on"' >> /etc/udev/rules.d/83-net-speed.rules
```

```
ethtool p0 | grep -P 'Speed|Auto'
ethtool p1 | grep -P 'Speed|Auto';

Output should look like this assuming it is connecting to a 25G port

	Speed: 25000Mb/s
	Auto-negotiation: on
```
