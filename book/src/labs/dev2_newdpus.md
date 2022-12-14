# New DPUs (Reno)

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

| owner          | hostname            | DPU BMC IP     | DPU BMC MAC Address | DPU OOB IP     | DPU OOB MAC       | DPU FW Version | DPU Serial   | DPU Part Num    | iDRAC / iLO IP | iDRAC MAC         | iDRAC Service Tag | iDRAC FW   | iDRAC BIOS | BMC Version | Secure Boot Disabled? | Prod / Dev Board | VPI | Rack # | Ansible Name    | Netbox Link                                    |
| -------------- | ------------------- | -------------- | ------------------- | -------------- | ----------------- | -------------- | ------------ | --------------- | -------------- | ----------------- | ----------------- | ---------- | ---------- | ----------- | --------------------- | ---------------- | --- | ------ | --------------- | ---------------------------------------------- |
| Doug           | rno1-m03-b17-cpu-08 | 10.180.221.232 | 4a:58:ec:06:36:d3   | 10.180.221.233 | 08:c0:eb:cb:0e:94 | 24.34.1002     | MT2150X11233 | MBF2H536C-CECOT | 10.180.221.225 | b0:7b:25:fe:c0:64 | BN9C5K3           | 5.10.50.15 | 1.7.5      | 2.8.2-34    | Yes                   | Dev              | No  | RACK 1 | rno1-m03-b17-08 | https://netbox.nvidia.com/dcim/devices/141227/ |
| Demo / Tareque | rno1-m03-b17-cpu-10 | 10.180.221.229 | 08:c0:eb:cb:0e:98   | 10.180.221.223 | 08:c0:eb:cb:0e:a4 | 24.34.1002     | MT2150X11234 | MBF2H536C-CECOT | 10.180.221.222 | b0:7b:25:d6:54:e8 | F54Q1G3           | 5.10.50.15 | 1.7.5      | 2.8.2-46    | Yes                   | Dev              | No  | RACK 1 | rno1-m03-b17-10 | https://netbox.nvidia.com/dcim/devices/132056/ |
| Shi Lu         | rno1-m03-b17-cpu-07 | 10.180.221.230 | b2:b5:46:3f:df:7f   | 10.180.221.236 | 08:c0:eb:cb:0e:04 | 24.34.1002     | MT2150X11224 | MBF2H536C-CECOT | 10.180.221.224 | b0:7b:25:fe:cc:f4 | 2P9C5K3           | 5.10.50.15 | 1.7.5      | 2.8.2-46    | Yes                   | Dev              | No  | RACK 1 | rno1-m03-b17-07 | https://netbox.nvidia.com/dcim/devices/141222/ |
| Ian            | rno1-m03-b17-cpu-11 | 10.180.221.231 | 08:c0:eb:cb:0d:e8   | 10.180.221.234 | 08:c0:eb:cb:0d:f4 | 24.34.1002     | MT2150X11223 | MBF2H536C-CECOT | 10.180.221.227 | b0:7b:25:fe:c9:d6 | 1P9C5K3           | 5.10.50.15 | 1.7.5      | 2.8.2-46    | Yes                   | Dev              | No  | RACK 1 | rno1-m03-b17-11 | https://netbox.nvidia.com/dcim/devices/141221/ |
| Mike           | rno1-m03-b17-cpu-09 | 10.180.221.228 | 08:c0:eb:cb:0e:18   | 10.180.221.235 | 08:c0:eb:cb:0e:24 | 24.34.1002     | MT2150X11226 | MBF2H536C-CECOT | 10.180.221.226 | b0:7b:25:e3:90:c2 | F53X1G3           | 5.10.50.15 | 1.7.5      | 2.8.2-46    | Yes                   | Dev              | No  | RACK 1 | rno1-m03-b17-09 | https://netbox.nvidia.com/dcim/devices/132057/ |
| Available      | rno1-m03-b18-cpu-11 | 10.180.222.253 | 08:c0:eb:cb:0e:c8   | 10.180.222.226 | 08:c0:eb:cb:0e:d4 | 24.34.1002     | MT2150X11237 | MBF2H536C-CECOT | 10.180.222.236 | b0:7b:25:fe:74:aa | FN9C5K3           | 5.10.50.15 | 1.7.5      | 2.8.2-46    | Yes                   | Dev              | No  | RACK 2 | rno1-m03-b18-11 | https://netbox.nvidia.com/dcim/devices/141229/ |
| Su             | rno1-m03-b18-cpu-08 | 10.180.222.238 | 36:fa:ff:1d:8f:61   | 10.180.222.240 | 08:c0:eb:cb:0e:34 | 24.34.1002     | MT2150X11227 | MBF2H536C-CECOT | 10.180.222.223 | b0:7b:25:fe:76:90 | DN9C5K3           | 5.10.50.15 | 1.7.5      | 2.8.2-46    | Yes                   | Dev              | No  | RACK 2 | rno1-m03-b18-08 | https://netbox.nvidia.com/dcim/devices/141225/ |
| Su             | rno1-m03-b19-cpu-08 | 10.180.222.254 | 42:70:53:e9:80:65   | 10.180.222.241 | 08:c0:eb:cb:0e:54 | 24.34.1002     | MT2150X11229 | MBF2H536C-CECOT | 10.180.222.232 | b0:7b:25:fe:78:28 | CN9C5K3           | 5.10.50.15 | 1.7.5      | 2.8.2-46    | Yes                   | Dev              | No  | RACK 2 | rno1-m03-b19-08 | https://netbox.nvidia.com/dcim/devices/141226/ |
| Abhi           | rno1-m03-b19-cpu-11 | 10.180.222.248 | 08:c0:eb:cb:0f:18   | 10.180.222.235 | 08:c0:eb:cb:0f:24 | 24.34.1002     | MT2150X11242 | MBF2H536C-CECOT | 10.180.222.237 | b0:7b:25:fe:c4:b4 | HN9C5K3           | 5.10.50.15 | 1.7.5      | 2.8.2-46    | Yes                   | Dev              | No  | RACK 2 | rno1-m03-b19-11 | https://netbox.nvidia.com/dcim/devices/141223/ |
| Available      | rno1-m03-b18-cpu-09 | 10.180.222.243 | 08:c0:eb:cb:0d:d8   | 10.180.222.224 | 08:c0:eb:cb:0d:e4 | 24.34.1002     | MT2150X11222 | MBF2H536C-CECOT | 10.180.222.231 | b0:7b:25:d7:1b:96 | 7LGW1G3           | 5.10.50.15 | 1.7.5      | 2.8.2-46    | Yes                   | Dev              | No  | RACK 2 | rno1-m03-b18-09 | https://netbox.nvidia.com/dcim/devices/132053/ |
| Shi Lu         | rno1-m03-b19-cpu-07 | 10.180.222.245 | 08:c0:eb:cb:0e:68   | 10.180.222.249 | 08:c0:eb:cb:0e:74 | 24.34.1002     | MT2150X11231 | MBF2H536C-CECOT | 10.180.222.225 | b0:7b:25:fe:cc:ca | GN9C5K3           | 5.10.50.15 | 1.7.5      | 2.8.2-46    | Yes                   | Dev              | No  | RACK 2 | rno1-m03-b19-07 | https://netbox.nvidia.com/dcim/devices/132053/ |
| Vishnu         | rno1-m03-b19-cpu-10 | 10.180.222.244 | 08:c0:eb:cb:0e:b8   | 10.180.222.250 | 08:c0:eb:cb:0e:c4 | 24.34.1002     | MT2150X11236 | MBF2H536C-CECOT | 10.180.222.228 | b0:7b:25:f6:d1:d2 | JN9C5K3           | 5.10.50.15 | 1.7.5      | 2.8.2-46    | Yes                   | Dev              | No  | RACK 2 | rno1-m03-b19-10 | https://netbox.nvidia.com/dcim/devices/141218/ |
| Doug           | rno1-m03-b18-cpu-10 | 10.180.222.229 | 08:c0:eb:cb:0e:78   | 10.180.222.242 | 08:c0:eb:cb:0e:84 | 24.34.1002     | MT2150X11232 | MBF2H536C-CECOT | 10.180.222.234 | b0:7b:25:fe:bb:36 | 4P9C5K3           | 5.10.50.15 | 1.7.5      | 2.8.2-46    | Yes                   | Dev              | No  | RACK 2 | rno1-m03-b18-10 | https://netbox.nvidia.com/dcim/devices/141228/ |
| Bas            | rno1-m03-b19-cpu-09 | 10.180.222.247 | 08:c0:eb:cb:0e:a8   | x.x.x.x        | 08:c0:eb:cb:0e:b4 | 24.34.1002     | MT2150X11235 | MBF2H536C-CECOT | 10.180.222.233 | b0:7b:25:fe:75:f4 | 3P9C5K3           | 5.10.50.15 | 1.7.5      | 2.8.2-46    | Yes                   | Dev              | No  | RACK 2 | rno1-m03-b19-09 | https://netbox.nvidia.com/dcim/devices/141219/ |
| Shi Lu         | rno1-m03-b18-cpu-07 | 10.180.222.222 | b2:28:8f:52:44:68   | 10.180.222.227 | 08:c0:eb:cb:0e:14 | 24.34.1002     | MT2150X11225 | MBF2H536C-CECOT | 10.180.222.230 | b0:7b:25:fd:d9:64 | 9N9C5K3           | 5.10.50.15 | 1.7.5      | 2.8.2-46    | Yes                   | Dev              | No  | RACK 2 | rno1-m03-b18-07 | https://netbox.nvidia.com/dcim/devices/141224/ |
