### Ansible Host files for the various Forge Labs

hosts-newdpus-dev2.forge:

```
;Dell iDRAC servers

[x86_host_bmcs]
dpu_1_host_bmc ansible_host=10.180.221.210
dpu_2_host_bmc ansible_host=10.180.221.195
dpu_3_host_bmc ansible_host=10.180.221.207
dpu_4_host_bmc ansible_host=10.180.221.209
dpu_5_host_bmc ansible_host=10.180.221.226
dpu_6_host_bmc ansible_host=10.180.222.198
dpu_7_host_bmc ansible_host=10.180.222.220
dpu_8_host_bmc ansible_host=10.180.222.224
dpu_9_host_bmc ansible_host=10.180.222.222
dpu_10_host_bmc ansible_host=10.180.222.196
dpu_11_host_bmc ansible_host=10.180.222.217
dpu_12_host_bmc ansible_host=10.180.222.221
dpu_13_host_bmc ansible_host=10.180.222.219
dpu_14_host_bmc ansible_host=10.180.222.223
dpu_15_host_bmc ansible_host=10.180.222.216

[x86_host_bmcs:vars]
ansible_user=root
ansible_password=M/uz{HKh@fz6S-%8

[dpus]
dpu_1 ansible_host=10.180.221.233 oob_mac=08:c0:eb:cb:0e:94
dpu_2 ansible_host=10.180.221.223 oob_mac=08:c0:eb:cb:0e:a4
dpu_3 ansible_host=10.180.221.236 oob_mac=08:c0:eb:cb:0e:04
dpu_4 ansible_host=10.180.221.234 oob_mac=08:c0:eb:cb:0d:f4
dpu_5 ansible_host=10.180.221.235 oob_mac=08:c0:eb:cb:0e:24
dpu_6 ansible_host=10.180.222.226 oob_mac=08:c0:eb:cb:0e:d4
dpu_7 ansible_host=10.180.222.240 oob_mac=08:c0:eb:cb:0e:34
dpu_8 ansible_host=10.180.222.241 oob_mac=08:c0:eb:cb:0e:54
dpu_9 ansible_host=10.180.222.235 oob_mac=08:c0:eb:cb:0f:24
dpu_10 ansible_host=10.180.222.224 oob_mac=08:c0:eb:cb:0d:e4
dpu_11 ansible_host=10.180.222.249 oob_mac=08:c0:eb:cb:0e:74
dpu_12 ansible_host=10.180.222.250 oob_mac=08:c0:eb:cb:0e:c4
dpu_13 ansible_host=10.180.222.242 oob_mac=08:c0:eb:cb:0e:84
;dpu_14 ansible_host=10.180.222.199 oob_mac=08:c0:eb:cb:0e:b4
dpu_15 ansible_host=10.180.222.227 oob_mac=08:c0:eb:cb:0e:14

[dpus:vars]
ansible_user=ubuntu
ansible_password=ubuntu

[dpu_bmcs]
dpu_1_bmc ansible_host=10.180.221.232 bmc_mac=4a:58:ec:06:36:d3
dpu_2_bmc ansible_host=10.180.221.229 bmc_mac=08:c0:eb:cb:0e:98
dpu_3_bmc ansible_host=10.180.221.230 bmc_mac=08:c0:eb:cb:0d:f8
dpu_4_bmc ansible_host=10.180.221.231 bmc_mac=08:c0:eb:cb:0d:e8
dpu_5_bmc ansible_host=10.180.221.228 bmc_mac=08:c0:eb:cb:0e:18
dpu_6_bmc ansible_host=10.180.222.239 bmc_mac=fe:a0:6a:6f:ae:b1
dpu_7_bmc ansible_host=10.180.222.238 bmc_mac=36:fa:ff:1d:8f:61
dpu_8_bmc ansible_host=10.180.222.246 bmc_mac=42:70:53:e9:80:65
dpu_9_bmc ansible_host=10.180.222.248 bmc_mac=08:c0:eb:cb:0f:18
dpu_10_bmc ansible_host=10.180.222.243 bmc_mac=08:c0:eb:cb:0d:d8
dpu_11_bmc ansible_host=10.180.222.245 bmc_mac=08:c0:eb:cb:0e:68
dpu_12_bmc ansible_host=10.180.222.244 bmc_mac=08:c0:eb:cb:0e:b8
dpu_13_bmc ansible_host=10.180.222.229 bmc_mac=08:c0:eb:cb:0e:78
dpu_14_bmc ansible_host=10.180.222.247 bmc_mac=08:c0:eb:cb:0e:a8
dpu_15_bmc ansible_host=10.180.222.222 bmc_mac=b2:28:8f:52:44:68

[dpu_bmcs:vars]
ansible_user=root
ansible_password=M/uz{HKh@fz6S-%8

[all:vars]
ansible_user=ubuntu
ansible_password=ubuntu
ansible_ssh_common_args='-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null'
discovered_interpreter_python="/usr/bin/python3"
```

hosts-integrration.forge

```
;Dell iDRAC servers

[x86_host_bmcs]
dpu_reno_int_1_host_bmc ansible_host=10.180.248.3
dpu_reno_int_2_host_bmc ansible_host=10.180.248.12
dpu_reno_int_3_host_bmc ansible_host=10.180.248.19

[dpus]
dpu_reno_int_1 ansible_host=10.180.248.5  oob_mac=10:70:fd:18:0f:fa
dpu_reno_int_2 ansible_host=10.180.248.13 oob_mac=08:c0:eb:cb:0e:a4
dpu_reno_int_3 ansible_host=10.180.248.21 oob_mac=08:c0:eb:cb:0e:04

[dpus:vars]
ansible_user=ubuntu
ansible_password=ubuntu

[dpu_bmcs]
dpu_reno_int_1_bmc ansible_host=10.180.248.6 bmc_mac=10:70:fd:18:0f:ee
dpu_reno_int_2_bmc ansible_host=10.180.248.14 bmc_mac=08:c0:eb:cb:0e:98
dpu_reno_int_3_bmc ansible_host=10.180.248.22 bmc_mac=08:c0:eb:cb:0d:f8

[all:vars]
ansible_user=root
ansible_password=M/uz{HKh@fz6S-%8
ansible_ssh_common_args='-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null'
discovered_interpreter_python="/usr/bin/python3"
```
