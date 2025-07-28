# Forge Managed Sites and System Types

The sites Forge manages vary in system count and configuration depending on the project.

## Azure

Azure is split into three phases of deployments:

Azure Phase 1:

- AZ01, AZ02, AZ05 (WUS - West US - San Jose)
- AZ03, AZ04, AZ06 (WUS2 - West US 2 - Wenatchee)
- AZ20 - AZ33 (SDC - Gavle, Sweden)

Azure Phase 2a:

- AZ40 (CNC - Toronto, Canada)
- AZ50 (JPN - Tokyo, Japan)
- AZ60 (GWC - Frankfurt, Germany)

Azure Phase 2b:

- AZ41 (CNC - Toronto, Canada)
- AZ51, AZ52 (JPW - Osaka, Japan)
- AZ61 (GWC - Frankfurt, Germany)

More details about the sites and contact information for Azure DCs can be found on the
[Operations Management](https://confluence.nvidia.com/display/NSV/Operations+Management) page in Confluence.

### System Types per Site

Phase 1 and 2a:

| | | | | | |
|---|---|---|---|---|---|
| Node Type | Vendor | Model | Component | Description | Quantity |
| GPU | Lenovo | ThinkSystem SR670 V2 | GPU | L40 | 8 |
| example: [J1050ACR](https://api-az01.frg.nvidia.com/admin/managed-host/fm100ht066u4lvbo7i3u6ubn4gt7gd0k6papoe2u11jrhglq9fud5njura0) | | | DPU | Bluefield 2 | 1 |
| | | | Infiniband | ConnectX-7 (100Gb) x 2 port | 2 |
| | | | CPU | Intel Platinum 8362 CPU @ 2.80GHz | 2 |
| | | | Memory | 1TB (64GB Sticks) | 16 |
| | | | Disks (boot) | 960GB M2 NVMe SSD | 2 |
| | | | Disks (data) | 7.68TB EDSFF NVMe SSD | 2 |
| Cache/CPU | Lenovo | ThinkSystem SR650 V2 OVX | GPU | N/a | 0 |
| example: [J10505TK](https://api-az01.frg.nvidia.com/admin/managed-host/fm100hta83ol6ma7c1fj5ishlmlom8qokbcc2e98l4e1e9gdajk18385k30) | | | DPU | Bluefield 2 | 1 |
| | | | CPU | Intel Platinum 8362 CPU @ 2.80GHz | 2 |
| | | | Memory | 512GB (32GB Sticks) | 16 |
| | | | Disks (boot) | 960GB M2 NVMe SSD | 2 |
| | | | Disks (data) | 1.92TB NVMe SSD | 2 |
| Storage (STG) | Lenovo | ThinkSystem SR650 V2 OVX | GPU | N/a | 0 |
| example: [J105004E](https://api-az01.frg.nvidia.com/admin/managed-host/fm100ht2cjvc1lkrp5844cl7b1rqjqk2618jmda7r72kr7c978l8njlp3p0) | | | DPU | Bluefield 2 | 1 |
| | | | CPU | Intel Platinum 8362 CPU @ 2.80GHz | 2 |
| | | | Memory | 1TB (64GB Sticks) | 16 |
| | | | Disks (boot) | 960GB M2 NVMe SSD | 2 |
| | | | Disks (data) | 1.92TB NVMe SSD | 16 |

Phase 2b Sites:

| | | | | | |
|---|---|---|---|---|---|
| Node Type | Vendor | Model | Component | Description | Quantity |
| GPU | Lenovo | ThinkSystem SR675 V3 OVX | GPU | L40S | 8 |
| example: [J701NE19](https://api-az52.frg.nvidia.com/admin/managed-host/fm100ht042aiefd76pk1728u2vr90bl0fms2s4nqsesvptq7dvs9uoujr3g) | | | DPU | Bluefield 3 | 1 |
| | | | Infiniband | ConnectX-7 (400Gb) x 1 port | 4 |
| | | | CPU | AMD EPYC 9334 @ 3.9 GHz | 2 |
| | | | Memory | 1TB (64GB Sticks) | 16 |
| | | | Disks (boot) | 960GB M2 NVMe SSD | 1 |
| | | | Disks (data) | 3.84TB EDSFF NVMe SSD | 2 |
| Cache/STR | Lenovo | ThinkSystem SR655 V3 OVX | GPU | N/a | 0 |
| example: [J10505TK](https://api-az52.frg.nvidia.com/admin/managed-host/fm100htu1vs83ns7u76pee2luj16mff2ugqgn7a47n98qtb3i7fh72ujbfg) | | | DPU | Bluefield 3 | 1 |
| | | | CPU | AMD EPYC 9334 @ 3.9 GHz  | 1 |
| | | | Memory | 384GB (32GB Sticks) | 12 |
| | | | Disks (boot) | 960GB M2 NVMe SSD | 1 |
| | | | Disks (data) | 3.84TB NVMe SSD | 1 |
| Storage (FBSTR) | Lenovo | ThinkSystem SR655 V3 OVX | GPU | N/a | 0 |
| example: [J701PXLA](https://api-az52.frg.nvidia.com/admin/managed-host/fm100htilk6iev7hfn154j3iutnrj3phrlebhci7u4etbl0nao2f44sj27g) | | | DPU | Bluefield 3 | 1 |
| | | | CPU | AMD EPYC 9334 @ 3.9 GHz  | 1 |
| | | | Memory | 384GB (32GB Sticks) | 12 |
| | | | Disks (boot) | 960GB M2 NVMe SSD | 2 |
| | | | Disks (data) | 7.68TB NVMe SSD | 8 |
| Cache (STR) | Lenovo | ThinkSystem SR665 V3 OVX | GPU | N/a | 0 |
| example: [J701PXKT](https://api-az52.frg.nvidia.com/admin/managed-host/fm100ht1bpaj83t2h027hleqgc5ep5of2q00ucbb49j7mn778pbfndmaj5g) | | | DPU | Bluefield 3 | 1 |
| | | | CPU | AMD EPYC 9334 @ 3.9 GHz  | 2 |
| | | | Memory | 1TB (64GB Sticks) | 16 |
| | | | Disks (boot) | 960GB M2 NVMe SSD | 1 |
