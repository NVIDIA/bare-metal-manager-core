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
| 10.180.222.15 |	10:70:fd:18:10:5e	| 10.180.222.13 |	10:70:fd:18:10:6a |	MT2203X26583 | rno1-m03-b17-cpu-02 - Security Team |
| 10.180.222.16 |	10:70:fd:18:0f:ee	| 10.180.222.35 |	10:70:fd:18:0f:fa |	MT2203X26576 ||
| 10.180.222.17 |	10:70:fd:18:0f:6e |	10.180.222.43 |	10:70:fd:18:0f:7a |	MT2203X26568 ||
| 10.180.222.19 |	10:70:fd:18:0f:0e |	10.180.222.25 |	10:70:fd:18:0f:1a |	MT2203X26562 ||
| 10.180.222.20 |	10:70:fd:18:0f:8e |	10.180.222.45 |	10:70:fd:18:0f:9a |	MT2203X26570 ||
| 10.180.222.21 |	10:70:fd:18:0f:2e |	10.180.222.14 |	10:70:fd:18:0f:3a |	MT2203X26564 | rno1-m03-b19-str-01 - Vishnu's |
| 10.180.222.23 |	10:70:fd:18:0f:fe |	10.180.222.46 |	10:70:fd:18:10:0a |	MT2203X26577 ||
| 10.180.222.26 |	10:70:fd:18:0f:ce |	10.180.222.47 |	10:70:fd:18:0f:da |	MT2203X26574 ||
| 10.180.222.27 |	10:70:fd:18:0f:5e |	10.180.222.48 |	10:70:fd:18:0f:6a |	MT2203X26567 ||
| 10.180.222.28 |	10:70:fd:18:0f:be |	10.180.222.10 |	10:70:fd:18:0f:ca |	MT2203X26573 | rno1-m03-b18-str-01 - Vishnu's |
| 10.180.222.29 |	10:70:fd:18:10:6e |	10.180.222.24 |	10:70:fd:18:10:7a |	MT2203X26584 | rno1-m03-b18-cpu-06 - Su's |
| 10.180.222.30 |	10:70:fd:18:10:0e |	10.180.222.31 |	10:70:fd:18:10:1a | MT2203X26578 | rno1-m03-b18-cpu-02 - control node |
| 10.180.222.33 |	10:70:fd:18:10:3e |	10.180.222.40 |	10:70:fd:18:10:4a	| MT2203X26581 | rno1-m03-b19-cpu-06 - Su's |
| 10.180.222.34 |	10:70:fd:18:0f:ae |	10.180.222.38 |	10:70:fd:18:0f:ba |	MT2203X26572 ||
| 10.180.222.36 |	10:70:fd:18:10:2e |	10.180.222.42 |	10:70:fd:18:10:3a | MT2203X26580 | rno1-m03-b19-cpu-01 - control node |
| 10.180.222.37 |	10:70:fd:18:0f:9e |	10.180.222.39 |	10:70:fd:18:0f:aa |	MT2203X26571 ||
| 10.180.222.41 |	10:70:fd:18:10:7e |	10.180.222.49 |	10:70:fd:18:10:8a |	MT2203X26585 |rno1-m03-b19-cpu-02 - Security Team |
| 10.180.222.53 |	6a:7c:1a:43:16:64 |	10.180.222.44 |	10:70:fd:18:10:5a |	MT2203X26582 | rno1-m03-b17-cpu-06 - Su's |
| 10.180.222.55	| 10:70:fd:18:0e:fe	| 10.180.222.54	| 10:70:fd:18:0f:0a |	MT2203X26561 ||

The following 3 nodes are the control plane and have manually set IPs with no dhcp helper on the switch.

Credentials
- OS: `ubuntu:ubuntu`
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

| ip | bmc ip | dpu sn |
| ---------- | ------------- | ---------- |
| 10.180.32.12 | 10.180.222.12 | NA - This is the Dell w/ a DPU card (bmc will be root/calvin) |
| 10.180.32.76 | 10.180.222.60 | MT2203X26573 |
| 10.180.32.140 | 10.180.222.59 | MT2203X26564 |

The following 2 nodes are a test env set up for Security/Gopi.

Credentials
- OS: `ubuntu:ubuntu`
- BMC: `ADMIN:ADMIN`
- Jumpbox: `155.130.12.194`

| ip | bmc ip | dpu sn |
| ---------- | ------------- | ---------- |
| 10.180.32.13 | 10.180.222.22 | MT2203X26583 |
| 10.180.32.141 | 10.180.222.61 | MT2203X26585 |

