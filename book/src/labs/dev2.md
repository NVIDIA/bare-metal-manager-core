# Dev2(Reno)

### Reno host info
There is not presently much information other than the DPUs BMCs in Reno. The machines are in unknown state
and the forge discovery image will reset the BMCs. DC Ops may have to set them all to pxe boot though.

Note: .53 is currently not responding as the x86 it was in died, it will come online when new gear arrives

Credentials
- ARM OS: `ubuntu:ubuntu`
- DPU BMC: `root:M/uz{HKh@fz6S-%8`

Details
- https://docs.google.com/spreadsheets/d/172XpZFYMAo_Ph98FMflqztnBE5fILUIeWe9b20R2cQE/edit#gid=0
- B17 - https://netbox.nvidia.com/dcim/racks/9953/
- B18 - https://netbox.nvidia.com/dcim/racks/9954/
- B19 - https://netbox.nvidia.com/dcim/racks/9955/

| BMC IP | BMC Eth | OOB IP | OOB Eth | Serial | In Use |
| ---------- | ------------- | ------------- | ------------- | ------------------- | ------------------- | 
| 10.180.222.11 |	10:70:fd:18:0f:3e	| 10.180.222.18 |	10:70:fd:18:0f:4a |	MT2203X26565 | rno1-m03-b17-cpu-01 - control node |
| 10.180.222.15 |	10:70:fd:18:10:5e	| 10.180.222.13 |	10:70:fd:18:10:6a |	MT2203X26583 | rno1-m03-b17-cpu-02 - dogfood |
| 10.180.222.16 |	10:70:fd:18:0f:ee	| 10.180.222.35 |	10:70:fd:18:0f:fa |	MT2203X26576 | rno1-m03-b18-cpu-03 - dogfood |
| 10.180.222.17 |	10:70:fd:18:0f:6e |	10.180.222.43 |	10:70:fd:18:0f:7a |	MT2203X26568 | rno1-m03-b19-cpu-04 - dogfood |
| 10.180.222.19 |	10:70:fd:18:0f:0e |	10.180.222.25 |	10:70:fd:18:0f:1a |	MT2203X26562 | rno1-m03-b18-cpu-05 - dogfood |
| 10.180.222.20 |	10:70:fd:18:0f:8e |	10.180.222.45 |	10:70:fd:18:0f:9a |	MT2203X26570 | rno1-m03-b19-cpu-03 - dogfood |
| 10.180.222.21 |	10:70:fd:18:0f:2e |	10.180.222.14 |	10:70:fd:18:0f:3a |	MT2203X26564 | rno1-m03-b19-str-01 - Vishnu's |
| 10.180.222.23 |	10:70:fd:18:0f:fe |	10.180.222.46 |	10:70:fd:18:10:0a |	MT2203X26577 | rno1-m03-b17-cpu-05 - dogfood |
| 10.180.222.26 |	10:70:fd:18:0f:ce |	10.180.222.47 |	10:70:fd:18:0f:da |	MT2203X26574 | rno1-m03-b17-cpu-04 - dogfood |
| 10.180.222.27 |	10:70:fd:18:0f:5e |	10.180.222.48 |	10:70:fd:18:0f:6a |	MT2203X26567 | rno1-m03-b19-cpu-05 - dogfood |
| 10.180.222.28 |	10:70:fd:18:0f:be |	10.180.222.10 |	10:70:fd:18:0f:ca |	MT2203X26573 | rno1-m03-b18-str-01 - Vishnu's |
| 10.180.222.29 |	10:70:fd:18:10:6e |	10.180.222.24 |	10:70:fd:18:10:7a |	MT2203X26584 | rno1-m03-b18-cpu-06 - Su's |
| 10.180.222.30 |	10:70:fd:18:10:0e |	10.180.222.31 |	10:70:fd:18:10:1a | MT2203X26578 | rno1-m03-b18-cpu-02 - control node |
| 10.180.222.33 |	10:70:fd:18:10:3e |	10.180.222.40 |	10:70:fd:18:10:4a	| MT2203X26581 | rno1-m03-b19-cpu-06 - Su's |
| 10.180.222.34 |	10:70:fd:18:0f:ae |	10.180.222.38 |	10:70:fd:18:0f:ba |	MT2203X26572 | no1-m03-b18-cpu-04 - dogfood |
| 10.180.222.36 |	10:70:fd:18:10:2e |	10.180.222.42 |	10:70:fd:18:10:3a | MT2203X26580 | rno1-m03-b19-cpu-01 - control node |
| 10.180.222.37 |	10:70:fd:18:0f:9e |	10.180.222.39 |	10:70:fd:18:0f:aa |	MT2203X26571 ||
| 10.180.222.41 |	10:70:fd:18:10:7e |	10.180.222.49 |	10:70:fd:18:10:8a |	MT2203X26585 |rno1-m03-b19-cpu-02 - dogfood |
| 10.180.222.53 |	6a:7c:1a:43:16:64 |	10.180.222.44 |	10:70:fd:18:10:5a |	MT2203X26582 | rno1-m03-b17-cpu-06 - Su's |
| 10.180.222.55	| 10:70:fd:18:0e:fe	| 10.180.222.54	| 10:70:fd:18:0f:0a |	MT2203X26561 ||

The following 3 nodes are the control plane and have manually set IPs with no dhcp helper on the switch.

Credentials
- OS: uses nvinit and membership in forge-dev-ssh-accesss group.
- BMC: `ADMIN:ADMIN`

| ip | bmc ip |
| ---------- | ------------- |
| 10.180.32.10 | 10.180.222.50 |
| 10.180.32.74 | 10.180.222.52 |
| 10.180.32.138 | 10.180.222.51 |

The following 3 nodes are a test env set up for Su.

Credentials
- OS: `ubuntu:ubuntu`
- BMC: `ADMIN:ADMIN`

| ip | bmc ip | dpu sn |
| ---------- | ------------- | ---------- |
| 10.180.32.11 | 10.180.222.57 | MT2203X26582 |
| 10.180.32.75 | 10.180.222.58 | MT2203X26584 |
| 10.180.32.139 | 10.180.222.56 | MT2203X26581 |

The following 3 nodes are a test env set up for Vishnu.

Credentials
- OS: `ubuntu:ubuntu`
- BMC: `ADMIN:ADMIN`

| x86 ip | x86 bmc ip | dpu oob ip | dpu port 0 ip | dpu port 1 ip | dpu sn | dpu bmc ip |
| ---------- | ------------- | ------------- | ------------- | ------------- | ---------- | ---------- |
| 10.180.32.12 | 10.180.222.12 | NA - This is the Dell w/ a DPU card (bmc will be root/calvin) | | | | |
| 10.180.32.76 | 10.180.222.60 | 10.180.222.10 | 10.180.32.110 | 10.180.96.110 | MT2203X26573 | 10.180.222.28 |
| 10.180.32.140 | 10.180.222.59 | 10.180.222.14 | 10.180.32.142 | 10.180.96.142 | MT2203X26564 | 10.180.222.21 |


### Dogfood setup
The dogfood setup manages the following units using forge site controller. It is a self-serving system that allow user to allocate x86 hosts on-demand (sort of).

The goal of dogfood is to discover missing features, design flaws, and bugs in forge site control and HBN via active usage. The dogfood setup currently exercise forge vpc, kea, and HBN componments. We will continue to add more components, features to dogfood as they become avaiable.

Credentials
- OS: `ubuntu:ubuntu`
- BMC: `ADMIN:ADMIN`

| host | host bmc ip | Owner |
| ---- | ----------- | ----- |
| rno1-m03-b17-cpu-04 | 10.180.222.64 | 
| rno1-m03-b17-cpu-05 | 10.180.222.65 |
| rno1-m03-b18-cpu-04 | 10.180.222.67 |
| rno1-m03-b18-cpu-05 | 10.180.222.68 |
| rno1-m03-b19-cpu-03 | 10.180.222.69 |
| rno1-m03-b19-cpu-04 | 10.180.222.70 |
| rno1-m03-b19-cpu-05 | 10.180.222.71 |


**Note: We currently using kubectl as a way to interact with forge vpc directly. Eventually this will be replaced by grpcurl interacting with forge-api server.**

Assuming you have access to the dev2 k8s cluster, you can see all available units. The MGMT-IP columne are IPs accessing DPUs via the oob_net interfaces; whereas HOST-IP column are IPs accessing the x86 hosts. You can ssh into the either DPU and x86 host to experiement, but not to change anything!! if HOST-IP column is empty on a leaf, it means the corresponding x86 host is reserved by someone, and is not avaible for genral access.


``` bash
kubectl --kubeconfig PATH_TO_KUBE_CONFIG get leaf -A
NAMESPACE      NAME                  MGMT-IP         MAINTENANCE   HOST-IP                     STATUS
forge-system   rno1-m03-b17-cpu-04   10.180.222.47                                             True
forge-system   rno1-m03-b17-cpu-05   10.180.222.46                                             True
forge-system   rno1-m03-b18-cpu-03   10.180.222.35                 {"pf0hpf":"10.180.124.3"}   True
forge-system   rno1-m03-b18-cpu-04   10.180.222.38                                             True
forge-system   rno1-m03-b18-cpu-05   10.180.222.25                 {"pf0hpf":"10.180.124.7"}   True
forge-system   rno1-m03-b19-cpu-03   10.180.222.45                 {"pf0hpf":"10.180.124.4"}   True
forge-system   rno1-m03-b19-cpu-04   10.180.222.43                 {"pf0hpf":"10.180.124.6"}   True
forge-system   rno1-m03-b19-cpu-05   10.180.222.48                 {"pf0hpf":"10.180.124.8"}   True
```

If you want to dedicated units for your work, and do not want others to touch them, consider placing your units onto a tenant. So that peope know these units are already in use, and will not mess with them. In the following example, we have allocated 3 x86 hosts to 2 different tenants, where x86 hosts can be accessed via HOSTIP column.

```bash
kubectl --kubeconfig PATH_TO_KUBE_CONFIG get managedresource -A
NAMESPACE      NAME              FABRIC-DEVICE         RESOURCEGROUP   HOSTIP           FABRICIP         STATUS
forge-system   e2e-control-1     rno1-m03-b17-cpu-05   e2e-control     10.180.124.132   10.180.124.132   True
forge-system   e2e-control-2     rno1-m03-b18-cpu-04   e2e-control     10.180.124.131   10.180.124.131   True
forge-system   shi-joji-host-1   rno1-m03-b17-cpu-04   shi-joji        10.180.124.82    10.180.124.82    True
```

Unfortunately at this monment, provisioning of x86 hosts to tenant requires some human interaction. If you plan to reserve some units for your work, please let suw@nvidia know, he will be happy provision some units on your behalf. 
