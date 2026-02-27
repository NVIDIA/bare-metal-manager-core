# Desired Firmware Versions
## Hosts: (Unit Tested Server)
### Update as of 2/20/2026
| Host                                | Support Site          | BMC/Management FW                          | Release Date/Status      | BIOS/UEFI           | LXPM                              | Release Date/Status        |
|-------------------------------------|-----------------------|--------------------------------------------|--------------------------|---------------------|-----------------------------------|----------------------------|
| GB200 NVL - Wiwynn                  | Wiwynn Support        | 25.06-2_NV_WW_02                           | 11/18/25                 | 1.3.2GA             | 1.3.2GA                           | 2/04/26                    |
| NVSwitch Tray - Wiwynn              | Wiwynn Support        | 1.3.2GA                                    | 2/4/26                   | 1.3.2GA             | 1.3.2GA                           | 2/4/26                     |
| GB200 Compute Tray (1RU)            | DGX                   | 1.3.2GA                                    | 12/09/25                 | 1.3.2GA             | 1.3.2GA                           | 12/09/25                   |
| NVSwitch Tray DGX                   | DGX                   | 1.3.2GA                                    | 12/09/25                 | 1.3.2GA             | 1.3.2GA                           | 12/09/25                   |
| Lenovo GB300 Compute Tray           | [Lenovo Support](https://datacentersupport.lenovo.com/us/en) | 3.0.0 | 9/4/25              | 1.0.0GA             | 1.0.0GA                           | 9/4/25                     |
| DGX H100                            | [DGX H100/H200 FW](https://docs.nvidia.com/dgx/dgxh100-fw-update-guide/index.html) | 25.06.27 (DGXH100_H200_25.06.4 pkg) | 09/2025 | 1.06.07 (DGXH100_H200_25.06.4 pkg) |              | 09/2025                    |
| Lenovo ThinkSystem SR670 V2         | [Lenovo Support](https://datacentersupport.lenovo.com/us/en) | 6.10               | 8/28/25                  | 3.30                | 3.31.01                           | 8/28/25                    |
| Lenovo ThinkSystem SR675 V3         | [Lenovo Support](https://datacentersupport.lenovo.com/us/en) | 14.10              | 9/30/25                  | 8.30                | 4.20.03                           | 9/14/25                    |
| Lenovo ThinkSystem SR675 V3 OVX*    | [Lenovo Support](https://datacentersupport.lenovo.com/us/en) | 14.10              | 9/30/25                  | 8.30                | 4.20.03                           | 9/14/25                    |
| Lenovo ThinkSystem SR650            | [Lenovo Support](https://datacentersupport.lenovo.com/us/en) | 10.40              | 9/3/2025                 | 4.30                | 2.13                              | 3/11/25                    |
| Lenovo ThinkSystem SR650 V3         | [Lenovo Support](https://datacentersupport.lenovo.com/us/en) | 6.92               | 9/17/2025                | 3.70                | 4.21.01                           | 9/14/25                    |
| Lenovo ThinkSystem SR650 V2         | [Lenovo Support](https://datacentersupport.lenovo.com/us/en) | 5.70               | 9/3/2025                 | 3.60                | 3.31.01                           | 8/6/25                     |
| Lenovo ThinkSystem SR650 V2 OVX*    | [Lenovo Support](https://datacentersupport.lenovo.com/us/en) | 5.70               | 9/2/2025                 | 3.60                | 3.31.01                           | 8/6/25                     |
| Lenovo ThinkSystem SR655 V3         | [Lenovo Support](https://datacentersupport.lenovo.com/us/en) | 5.80               | 9/12/25                  | 5.70                | 4.20.03                           | 9/14/25                    |
| Lenovo ThinkSystem SR655 V3 OVX*    | [Lenovo Support](https://datacentersupport.lenovo.com/us/en) | 5.80               | 9/12/25                  | 5.70                | 4.20.03                           | 9/14/25                    |
| Lenovo ThinkSystem SR665 V3 OVX*    | [Lenovo Support](https://datacentersupport.lenovo.com/us/en) | 5.80               | 9/12/25                  | 5.70                | 4.20.03                           | 9/14/25                    |
| Lenovo SR650 V4                     | [Lenovo Support](https://datacentersupport.lenovo.com/us/en) | 1.90               | 1/12/26                  | 1.30                | 5.03.00                           | 11/27/25                   |
| Lenovo HS350X V3                    | [Lenovo Support](https://datacentersupport.lenovo.com/us/en) | 1.20               | 1/19/26                  | 2.17.0              |                                   | 6/15/25                    |
| Dell PowerEdge XE9680               | [Dell Support](https://www.dell.com/support/home/en-al/products) | iDRAC 7.20.60.50   | 9/1/25                   | 2.7.4               | 1.6.0                             | 9/1/25                     |
| Dell PowerEdge R750                 | [Dell Support](https://www.dell.com/support/home/en-al/products) | iDRAC 7.20.60.50   | 9/1/25                   | 1.18.1              | 1.1.1                             | 9/1/25                     |
| SYS-221H-TNR                        | [SMC Support](https://www.supermicro.com/en/support/resources/downloadcenter/swdownload) | 1.03.18  | 2/20/25         | 2.7                 | SAA Ver = 1.3.0-p7                | 08/04/25                   |
| Dell PowerEdge R760                 | [Dell Support](https://www.dell.com/support/home/en-al/products) | iDRAC 7.20.60.50   | 9/1/25                   | 2.7.5               | 1.2.6                             | 9/1/25                     |
| ARS-121L-DNR                        | [SMC Support](https://www.supermicro.com/en/support/resources/downloadcenter/swdownload) | 01.08.02 / 01.03.16 (LCC) | 12/19/25 / 7/31/24 | 2.2a / 2.0 (LCC) | SAA Ver = 1.2.0-p6 / SUM = 2.14.0-p6 (LCC) | 12/18/25 / 8/22/24 |
| SYS-221H-TN24R                      | [SMC Support](https://www.supermicro.com/en/support/resources/downloadcenter/swdownload) | X1.05.10 | 9/12/25         | 2.7                 | SAA Ver = 1.3.0-p5                | 7/11/25                    |
| ARS-221GL-NR                        | [SMC Support](https://www.supermicro.com/en/support/resources/downloadcenter/swdownload) | 1.03.16  | 7/1/24          | 2.0                 |                                   | 7/12/24                    |
| HPE ProLiant DL385 Gen10 Plus v2    | [HPE Support](https://support.hpe.com/connect/s/?language=en_US) | 3.15               | 8/13/25                  | 3.80_09-05-2025     |                                   | 9/12/25                    |
| DL380 Gen12                         | [HPE Support](https://support.hpe.com/connect/s/?language=en_US) | 1.20.00            | 2/16/26                  | 1.62_02-06-2026     |                                   | 2/16/26                    |
| SSG-121E-NES24R                     | [SMC Support](https://www.supermicro.com/en/support/resources/downloadcenter/swdownload) | 01.04.19 | 6/7/25          | 2.7                 | SAA Ver = 1.3.0-p1                | 7/17/25                    |
| SYS-121H-TNR                        | [SMC Support](https://www.supermicro.com/en/support/resources/downloadcenter/swdownload) | X1.05.10 | 9/12/25         | 2.7                 | SAA Ver = 1.3.0-p5                | 7/11/25                    |
| SYS-821GE-TNHR                      | [SMC Support](https://www.supermicro.com/en/support/resources/downloadcenter/swdownload) | 1.03.18  | 2/20/25         | 2.7                 | SAA Ver = 1.3.0-p7                | 08/04/25                   |
| Dell R760xd2                        | [Dell Support](https://www.dell.com/support/home/en-al/products) | iDRAC 7.20.80.50   | 1/1/26                   | 2.9.4               | 1.1.2                             | 1/1/26                     |
| Dell R670                           | [Dell Support](https://www.dell.com/support/home/en-al/products) | iDRAC 1.20.80.51   | 1/1/26                   | 1.7.5               |                                   | 1/1/26                     |
| Dell R770                           | [Dell Support](https://www.dell.com/support/home/en-al/products) | iDRAC 1.20.80.51   | 1/1/26                   | 1.7.5               |                                   | 1/1/26                     |
| SYS-421GE-TNRT                      | [SMC Support](https://www.supermicro.com/en/support/resources/downloadcenter/swdownload) | 1.03.19  | 5/8/25          | 2.6                 | SAA Ver = 1.2.0-p8                | 5/21/25                    |
| Dell PowerEdge R640                 | [Dell Support](https://www.dell.com/support/home/en-al/products) | iDRAC 7.00.00.182  | 8/21/25                  | 2.24.0              | 1.0.6                             | 5/13/25                    |

Note: * OVX does not show up as an option; need to check with Server Serial Number.

## DPU
| DPU          | Firmware / Software Version                       |
|--------------|---------------------------------------------------|
| Bluefield-2  | DOCA 3.2.0                                        |
| Bluefield-3  | DOCA 3.2.0                                        |
