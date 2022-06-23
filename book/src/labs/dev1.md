# Dev1(sjc4)

### Host info
Related Info about Lab hosts:

Jira <https://jirasw.nvidia.com/browse/NSVIS-3666>

Google Doc <https://docs.google.com/spreadsheets/d/1wbRW8zcw_rx05fgP6ThK288d0W_WRIVe6uErUpqT0Eg/edit?userstoinvite=rdancel@nvidia.com&actionButton=1#gid=2074715696>

Netbox <https://netbox.nvidia.com/dcim/racks/6496/>



| hostname   | DPU BMC IP    | DPU OOB IP    | HOST OOB IP   | HOST IP                          | DPU BMC Credentials | DPU OOB Credentials | HOST OOB ILO Creds    | Host OS Creds   |
| ---------- | ------------- | ------------- | ------------- | -------------------------------- | ------------------- | ------------------- | --------------------- | --------------  |
| forge001   | 10.146.38.232 | 10.146.38.229 | 10.146.38.242 | 10.150.51.235 / 10.150.51.236    | `root/0penBmc123`   | `ubuntu:ubuntu`     | `sjc4dcops:sjc4dcops` | `ubuntu:ubuntu` |
| forge002   | 10.146.38.231 | 10.146.38.247 | 10.146.38.243 | 10.150.51.242 / 10.150.115.235  | `root:M/uz{HKh@fz6S-%8`   | `ubuntu:ubuntu`     | `sjc4dcops:sjc4dcops` | `ubuntu:ubuntu` |
| forge003   | 10.146.38.241 | 10.146.38.240 | 10.146.38.244 | 10.150.51.230 / 10.150.115.242    | `root:M/uz{HKh@fz6S-%8`   | `ubuntu:ubuntu`     | `sjc4dcops:sjc4dcops` | `ubuntu:ubuntu` |
| forge004   | 10.146.38.235 | 10.146.38.226 | 10.146.38.245 | Dynamic                          | `root/0penBmc123`   | `ubuntu:ubuntu`     | `sjc4dcops:sjc4dcops` | `ubuntu:ubuntu` |
| forge005   | 10.146.38.236 | 10.146.38.225 | 10.146.38.246 | Dynamic                          | `root/0penBmc123`   | `ubuntu:ubuntu`     | `sjc4dcops:sjc4dcops` | `ubuntu:ubuntu` |

### BGP Info

| Device_A_name   | Device_A_Nic | IP Address     | Device_A_Loopback | Device_A_ASN | Peer_IP	Peer  | ASN   |
|-----------------|--------------|----------------|-------------------|--------------|----------------|-------|
| sjc4-d32-nv-01  | dpu_nic0     | 10.150.51.200  | 10.145.0.80       | 65280        | 10.150.51.193  | 65240 |
| sjc4-d32-nv-01  | dpu_nic1     | 10.150.115.200 | 10.145.0.81       | 65281        | 10.150.115.193 | 65240 |
| sjc4-d32-nv-02  | dpu_nic0     | 10.150.51.201  | 10.145.0.82       | 65280        | 10.150.51.193  | 65240 |
| sjc4-d32-nv-02  | dpu_nic1     | 10.150.115.201 | 10.145.0.83       | 65281        | 10.150.115.193 | 65240 |
| sjc4-d32-nv-03  | dpu_nic0     | 10.150.51.202  | 10.145.0.84       | 65280        | 10.150.51.193  | 65240 |
| sjc4-d32-nv-03  | dpu_nic1     | 10.150.115.202 | 10.145.0.85       | 65281        | 10.150.115.193 | 65240 |
| sjc4-d32-cpu-01 | dpu_nic0     | Unnumbered     | Dynamic           | Dynamic      | 10.150.51.193  | 65240 |
| sjc4-d32-cpu-01 | dpu_nic1     | Unnumbered     | Dynamic           | Dynamic      | 10.150.115.193 | 65240 |
| sjc4-d32-cpu-02 | dpu_nic0     | Unnumbered     | Dynamic           | Dynamic       | 10.150.51.193  | 65240 |
| sjc4-d32-cpu-02 | dpu_nic1     | Unnumbered     | Dynamic           | Dynamic        | 10.150.115.193 | 65240 |

Note: **Dynamic** indicates resources are managed by Forge, and Forge allocates these resources from [SJC4 Forge Dev](https://docs.google.com/spreadsheets/d/1wbRW8zcw_rx05fgP6ThK288d0W_WRIVe6uErUpqT0Eg/edit#gid=701174353).

