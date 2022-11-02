# Integration (Reno)

WORK IN PROGRESS

Credentials

- ARM OS: `ubuntu:ubuntu`
- DPU BMC: `root:M/uz{HKh@fz6S-%8`
- iLO / iDRAC: `root:M/uz{HKh@fz6S-%8`
- UEFI: `bluefield123`

Default Credentials:

- ARM OS: `ubuntu:ubuntu`
- DPU BMC: `root:0penBmc`
- iLO / iDRAC: `root:<the password is on the physical iDRAC device>`
- UEFI: `bluefield`

| owner          | hostname           | HBN Loopback | HBN ASN    | HBN Host Network | DPU BMC IP    | DPU BMC MAC Address | DPU OOB IP    | DPU OOB MAC       | DPU FW Version | DPU Serial   | DPU Part Num      | HOST IP       | iDRAC / iLO IP | iDRAC Service Tag | iDRAC FW   | iDRAC BIOS | BMC Version | BFB Image            | Secure Boot Disabled? | Prod / Dev Board | VPI | Ansible Name   | Netbox Link                                    |
| -------------- | ------------------ | ------------ | ---------- | ---------------- | ------------- | ------------------- | ------------- | ----------------- | -------------- | ------------ | ----------------- | ------------- | -------------- | ----------------- | ---------- | ---------- | ----------- | -------------------- | --------------------- | ---------------- | --- | -------------- | ---------------------------------------------- |
| Control Node 1 | rno1-m04-d01-cpu-1 | 10.180.62.1  | 4244766821 | 10.180.248.24/31 | 10.180.248.6  | 10:70:fd:18:0f:ee   | 10.180.248.5  | 10:70:fd:18:0f:fa | 24.34.1002     | MT2203X26576 | MBF2M516C-EESO_Ax | 10.180.248.25 | 10.180.248.3   | HMPV0R3           | 5.10.30.00 | 1.6.5      | 2.8.2-34    | DOCA 1.5 / 3.9.3 HBN | Yes                   | Prod             | Yes | dpu_reno_int_1 | https://netbox.nvidia.com/dcim/devices/187738/ |
| Control Node 2 | rno1-m04-d02-cpu-1 | 10.180.62.2  | 4244766822 | 10.180.248.26/31 | 10.180.248.14 | 10:70:fd:18:10:5e   | 10.180.248.13 | 10:70:fd:18:10:6a | 24.34.1002     | MT2203X26583 | MBF2M516C-EESO_Ax | 10.180.248.27 | 10.180.248.12  | 3NPV0R3           | 5.10.30.00 | 1.6.5      | 2.8.2-34    | DOCA 1.5 / 3.9.3 HBN | Yes                   | Prod             | Yes | dpu_reno_int_2 | https://netbox.nvidia.com/dcim/devices/187746/ |
| Control Node 3 | rno1-m04-d03-cpu-1 | 10.180.62.3  | 4244766823 | 10.180.248.28/31 | 10.180.248.22 | 10:70:fd:18:10:7e   | 10.180.248.21 | 10:70:fd:18:10:8a | 24.34.1002     | MT2203X26576 | MBF2M516C-EESO_Ax | 10.180.248.29 | 10.180.248.19  | 1NPV0R3           | 5.10.30.00 | 1.6.5      | 2.8.2-34    | DOCA 1.5 / 3.9.3 HBN | Yes                   | Prod             | Yes | dpu_reno_int_3 | https://netbox.nvidia.com/dcim/devices/187745/ |
