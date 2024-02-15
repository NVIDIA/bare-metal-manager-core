# Forge Site DPU SSH Access
## Prerequisites
In order to retrieve ssh credentials for a DPU, control plane and `forge-admin-cli` access is required.
 * See [Forge Site Controleer control plane node SSH access](control_plane_ssh_access.md) for control plane node access.
 * See [forge-admin-cli access on a Forge cluster](forge_admin_cli.md) for cli access.
 * All examples assume ssh config includes entries for the jump box and control plane node

The machine id of the dpu is known

## Get the DPU IP address
1. ssh to control plane node
2. get admin shell using `sudo su -`
3. get pod shell using `kubectl exec -ti deploy/carbide-api -n forge-system -- bash`
4. get ip from output of
    `/opt/carbide/forge-admin-cli -c https://${CARBIDE_API_SERVICE_HOST}:${CARBIDE_API_SERVICE_PORT} machine show --machine=<dpu-machine-id>`
5. get credentials for DPU account
    `/opt/carbide/forge-admin-cli -c https://${CARBIDE_API_SERVICE_HOST}:${CARBIDE_API_SERVICE_PORT} machine dpu-ssh-credentials --query=<dpu-machine-id>`

### Example for dev3 (actual credentials not shown):
```
$  ssh dev3
***********************************************************************
Use of this network is restricted to authorized users only.
All access attempts and activities on this network are subject to being
monitored, logged and audited.

The network operator reserves the right to consent to valid law
enforcement requests to search the network and to institute legal or
disciplinary action against any misuse of the network.
***********************************************************************
Welcome to Ubuntu 20.04.5 LTS (GNU/Linux 5.4.0-135-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage
Last login: Thu Jun  1 18:22:22 2023 from 10.180.49.149
$sudo su -
sudo: unable to resolve host pdx01-m01-h16-cpu-1.fc.nvda.co: Name or service not known
root@pdx01-m01-h16-cpu-1:~# kubectl exec -ti deploy/carbide-api -n forge-system -- bash
root@carbide-api-c9bc8dfd4-nv4p2:/# /opt/carbide/forge-admin-cli -c https://${CARBIDE_API_SERVICE_HOST}:${CARBIDE_API_SERVICE_PORT} machine show --machine=fm100ds43kv7l7rf65r7cnfslnuv0n9jk98arf5urer08hik89avejlhngg
IGNORING SERVER CERT, Please ensure that I am removed to actually validate TLS.
ID           : fm100ds43kv7l7rf65r7cnfslnuv0n9jk98arf5urer08hik89avejlhngg
CREATED      : 2023-05-31T20:40:02.087017Z
UPDATED      : 2023-06-01T18:46:50.670725Z
DEPLOYED     : 1970-01-01T00:00:00Z
STATE        : READY
MACHINE TYPE : DPU
STATE HISTORY: (Latest 5 only)
	Id    State                                                                                                 Time
	----------------------------------------------------------------------------------------------------------------------------
	1470  Host/WaitingForDiscovery                                                                            2023-05-31T20:49:50.616659Z
	1476  Host/WaitingForLockdown { lockdown_info: LockdownInfo { state: TimeWaitForDPUDown, mode: Enable } } 2023-06-01T00:24:22.752411Z
	1478  Host/WaitingForLockdown { lockdown_info: LockdownInfo { state: WaitForDPUUp, mode: Enable } }       2023-06-01T00:29:42.039967Z
	1480  Host/Discovered                                                                                     2023-06-01T00:30:18.081928Z
	1482  Ready                                                                                               2023-06-01T00:33:25.713703Z
INTERFACES:
	SN           : 0
	ID           : 3aedd1bc-c518-40ca-9fba-49842851a73a
	DPU ID       : fm100ds43kv7l7rf65r7cnfslnuv0n9jk98arf5urer08hik89avejlhngg
	Machine ID   : fm100ds43kv7l7rf65r7cnfslnuv0n9jk98arf5urer08hik89avejlhngg
	Segment ID   : ecbb7320-a131-4c5b-bb44-13414969e11d
	Domain ID    : 3ab627f6-c86f-4970-a35e-1a3f9a9b3d0c
	Hostname     : leopard-floor
	Primary      : true
	MAC Address  : B8:3F:D2:90:98:32
	Addresses    : 10.217.133.81/32
	--------------------------------------------------

root@carbide-api-c9bc8dfd4-nv4p2:/# /opt/carbide/forge-admin-cli -f json -c https://${CARBIDE_API_SERVICE_HOST}:${CARBIDE_API_SERVICE_PORT} machine dpu-ssh-credentials --query=fm100ds43kv7l7rf65r7cnfslnuv0n9jk98arf5urer08hik89avejlhngg
IGNORING SERVER CERT, Please ensure that I am removed to actually validate TLS.
{
  "username": "xxxxx",
  "password": "yyyyyyy"
}
root@carbide-api-c9bc8dfd4-nv4p2:/# exit
exit
root@pdx01-m01-h16-cpu-1:~# exit
logout
$exit
logout
Connection to 10.217.4.197 closed.

$ ssh xxxxx@10.217.133.81
***********************************************************************
Use of this network is restricted to authorized users only.
All access attempts and activities on this network are subject to being
monitored, logged and audited.

The network operator reserves the right to consent to valid law
enforcement requests to search the network and to institute legal or
disciplinary action against any misuse of the network.
***********************************************************************
xxxxx@10.217.133.81's password: 
Welcome to Ubuntu 20.04.5 LTS (GNU/Linux 5.4.0-1054.44.g88324c5-bluefield aarch64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Thu Jun  1 18:50:44 UTC 2023

  System load:                  0.31
  Usage of /:                   14.2% of 37.90GB
  Memory usage:                 23%
  Swap usage:                   0%
  Processes:                    529
  Users logged in:              1
  IPv4 address for br-mgmt:     10.88.0.1
  IPv6 address for br-mgmt:     2001:4860:4860::1
  IPv4 address for docker0:     172.17.0.1
  IPv4 address for mgmt:        127.0.0.1
  IPv6 address for mgmt:        ::1
  IPv4 address for oob_net0:    10.217.133.81
  IPv4 address for tmfifo_net0: 192.168.100.2

  => There is 1 zombie process.


 * Introducing Expanded Security Maintenance for Applications.
   Receive updates to over 25,000 software packages with your
   Ubuntu Pro subscription. Free for personal use.

     https://ubuntu.com/pro

0 updates can be applied immediately.

New release '22.04.2 LTS' available.
Run 'do-release-upgrade' to upgrade to it.


Last login: Thu Jun  1 18:07:12 2023 from 10.180.49.149
To run a command as administrator (user "root"), use "sudo <command>".
See "man sudo_root" for details.

xxxxx@leopard-floor:mgmt:~$ 

```

### Compressed dev3 Example (note the quoting):
```
ssh -t dev3 sudo kubectl exec -ti deploy/carbide-api -n forge-system -- bash -c "'"'/opt/carbide/forge-admin-cli -c https://${CARBIDE_API_SERVICE_HOST}:${CARBIDE_API_SERVICE_PORT} machine show --machine=fm100ds43kv7l7rf65r7cnfslnuv0n9jk98arf5urer08hik89avejlhngg && /opt/carbide/forge-admin-cli -c https://${CARBIDE_API_SERVICE_HOST}:${CARBIDE_API_SERVICE_PORT} machine dpu-ssh-credentials --query=fm100ds43kv7l7rf65r7cnfslnuv0n9jk98arf5urer08hik89avejlhngg'"'"
```

### Convenience Script (requires sshpass)
There is a script in `dev/bin` that does all this already:

interactive shell:
```
$ dev/bin/ssh_dpu.sh dev3 fm100ds43kv7l7rf65r7cnfslnuv0n9jk98arf5urer08hik89avejlhngg
***********************************************************************
Use of this network is restricted to authorized users only.
All access attempts and activities on this network are subject to being
monitored, logged and audited.

The network operator reserves the right to consent to valid law
enforcement requests to search the network and to institute legal or
disciplinary action against any misuse of the network.
***********************************************************************
Welcome to Ubuntu 20.04.5 LTS (GNU/Linux 5.4.0-1054.44.g88324c5-bluefield aarch64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Thu Jun  1 20:14:06 UTC 2023

  System load:                  0.73
  Usage of /:                   14.3% of 37.90GB
  Memory usage:                 23%
  Swap usage:                   0%
  Processes:                    539
  Users logged in:              1
  IPv4 address for br-mgmt:     10.88.0.1
  IPv6 address for br-mgmt:     2001:4860:4860::1
  IPv4 address for docker0:     172.17.0.1
  IPv4 address for mgmt:        127.0.0.1
  IPv6 address for mgmt:        ::1
  IPv4 address for oob_net0:    10.217.133.81
  IPv4 address for tmfifo_net0: 192.168.100.2

  => There is 1 zombie process.


 * Introducing Expanded Security Maintenance for Applications.
   Receive updates to over 25,000 software packages with your
   Ubuntu Pro subscription. Free for personal use.

     https://ubuntu.com/pro

0 updates can be applied immediately.

New release '22.04.2 LTS' available.
Run 'do-release-upgrade' to upgrade to it.


Last login: Thu Jun  1 20:06:39 2023 from 10.180.49.149
To run a command as administrator (user "root"), use "sudo <command>".
See "man sudo_root" for details.

forge@leopard-floor:mgmt:~$ 

```

Non-interactive run:
```
$ dev/bin/ssh_dpu.sh dev3 fm100ds43kv7l7rf65r7cnfslnuv0n9jk98arf5urer08hik89avejlhngg ls -l /
***********************************************************************
Use of this network is restricted to authorized users only.
All access attempts and activities on this network are subject to being
monitored, logged and audited.

The network operator reserves the right to consent to valid law
enforcement requests to search the network and to institute legal or
disciplinary action against any misuse of the network.
***********************************************************************
total 64
lrwxrwxrwx   1 root root     7 Jan 11 21:41 bin -> usr/bin
drwxr-xr-x   4 root root  4096 May 31 20:32 boot
drwxr-xr-x  16 root root  4480 Jun  1 00:32 dev
drwxr-xr-x 143 root root 12288 May 31 20:43 etc
drwxr-xr-x   4 root root  4096 May 31 20:40 home
lrwxrwxrwx   1 root root     7 Jan 11 21:41 lib -> usr/lib
drwx------   2 root root 16384 May 31 20:30 lost+found
drwxr-xr-x   2 root root  4096 Jan 11 21:41 media
drwxr-xr-x   2 root root  4096 Jan 11 21:41 mnt
drwxr-xr-x   8 root root  4096 May 31 20:43 opt
dr-xr-xr-x 593 root root     0 Jan  1  1970 proc
drwx------   3 root root  4096 May 31 21:25 root
drwxr-xr-x  35 root root  2140 Jun  1 20:09 run
lrwxrwxrwx   1 root root     8 Jan 11 21:41 sbin -> usr/sbin
drwxr-xr-x   2 root root  4096 Jan 11 21:41 srv
dr-xr-xr-x  12 root root     0 Jun  1 00:27 sys
drwxrwxrwt  14 root root   340 Jun  1 20:09 tmp
drwxr-xr-x  11 root root  4096 Jan 11 21:43 usr
drwxr-xr-x  14 root root  4096 Jan 31 10:22 var

```