### Ansible Host files for the Forge Labs

hosts-newdpus-dev2.forge:

```
;Dell iDRAC servers

[x86_host_bmcs]
rno1-m03-b17-08_host_bmc ansible_host=10.180.221.225
rno1-m03-b17-10_host_bmc ansible_host=10.180.221.222
rno1-m03-b17-07_host_bmc ansible_host=10.180.221.224
rno1-m03-b17-11_host_bmc ansible_host=10.180.221.227
rno1-m03-b17-09_host_bmc ansible_host=10.180.221.226
rno1-m03-b18-11_host_bmc ansible_host=10.180.222.236
rno1-m03-b18-08_host_bmc ansible_host=10.180.222.223
rno1-m03-b19-08_host_bmc ansible_host=10.180.222.232
rno1-m03-b19-11_host_bmc ansible_host=10.180.222.237
rno1-m03-b18-09_host_bmc ansible_host=10.180.222.232
rno1-m03-b19-07_host_bmc ansible_host=10.180.222.225
rno1-m03-b19-10_host_bmc ansible_host=10.180.222.228
rno1-m03-b18-10_host_bmc ansible_host=10.180.222.234
rno1-m03-b19-09_host_bmc ansible_host=10.180.222.233
rno1-m03-b18-07_host_bmc ansible_host=10.180.222.230

[x86_host_bmcs:vars]
ansible_user=root
ansible_password=M/uz{HKh@fz6S-%8

[dpus]
rno1-m03-b17-08 ansible_host=10.180.221.233 oob_mac=08:c0:eb:cb:0e:94
rno1-m03-b17-10 ansible_host=10.180.221.223 oob_mac=08:c0:eb:cb:0e:a4
rno1-m03-b17-07 ansible_host=10.180.221.236 oob_mac=08:c0:eb:cb:0e:04
rno1-m03-b17-11 ansible_host=10.180.221.234 oob_mac=08:c0:eb:cb:0d:f4
rno1-m03-b17-09 ansible_host=10.180.221.235 oob_mac=08:c0:eb:cb:0e:24
rno1-m03-b18-11 ansible_host=10.180.222.226 oob_mac=08:c0:eb:cb:0e:d4
rno1-m03-b18-08 ansible_host=10.180.222.240 oob_mac=08:c0:eb:cb:0e:34
rno1-m03-b19-08 ansible_host=10.180.222.241 oob_mac=08:c0:eb:cb:0e:54
rno1-m03-b19-11 ansible_host=10.180.222.235 oob_mac=08:c0:eb:cb:0f:24
rno1-m03-b18-09 ansible_host=10.180.222.224 oob_mac=08:c0:eb:cb:0d:e4
rno1-m03-b19-07 ansible_host=10.180.222.249 oob_mac=08:c0:eb:cb:0e:74
rno1-m03-b19-10 ansible_host=10.180.222.250 oob_mac=08:c0:eb:cb:0e:c4
rno1-m03-b18-10 ansible_host=10.180.222.242 oob_mac=08:c0:eb:cb:0e:84
;rno1-m03-b19-09 ansible_host=10.180.222.199 oob_mac=08:c0:eb:cb:0e:b4
rno1-m03-b18-07 ansible_host=10.180.222.227 oob_mac=08:c0:eb:cb:0e:14

[dpus:vars]
ansible_user=ubuntu
ansible_password=ubuntu

[dpu_int_bmcs]
rno1-m03-b17-08_bmc ansible_host=10.180.221.232 bmc_mac=4a:58:ec:06:36:d3
rno1-m03-b17-10_bmc ansible_host=10.180.221.229 bmc_mac=08:c0:eb:cb:0e:98
rno1-m03-b17-07_bmc ansible_host=10.180.221.230 bmc_mac=08:c0:eb:cb:0d:f8
rno1-m03-b17-11_bmc ansible_host=10.180.221.231 bmc_mac=08:c0:eb:cb:0d:e8
rno1-m03-b17-09_bmc ansible_host=10.180.221.228 bmc_mac=08:c0:eb:cb:0e:18
rno1-m03-b18-11_bmc ansible_host=10.180.222.239 bmc_mac=fe:a0:6a:6f:ae:b1
rno1-m03-b18-08_bmc ansible_host=10.180.222.238 bmc_mac=36:fa:ff:1d:8f:61
rno1-m03-b19-08_bmc ansible_host=10.180.222.246 bmc_mac=42:70:53:e9:80:65
rno1-m03-b19-11_bmc ansible_host=10.180.222.248 bmc_mac=08:c0:eb:cb:0f:18
rno1-m03-b18-09_bmc ansible_host=10.180.222.243 bmc_mac=08:c0:eb:cb:0d:d8
rno1-m03-b19-07_bmc ansible_host=10.180.222.245 bmc_mac=08:c0:eb:cb:0e:68
rno1-m03-b19-10_bmc ansible_host=10.180.222.244 bmc_mac=08:c0:eb:cb:0e:b8
rno1-m03-b18-10_bmc ansible_host=10.180.222.229 bmc_mac=08:c0:eb:cb:0e:78
rno1-m03-b19-09_bmc ansible_host=10.180.222.247 bmc_mac=08:c0:eb:cb:0e:a8
rno1-m03-b18-07_bmc ansible_host=10.180.222.222 bmc_mac=b2:28:8f:52:44:68

[dpu_int_bmcs:vars]
ansible_user=root
ansible_password=M/uz{HKh@fz6S-%8

[all:vars]
ansible_user=ubuntu
ansible_password=ubuntu
ansible_ssh_common_args='-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null'
discovered_interpreter_python="/usr/bin/python3"
```

hosts-integration-nodes.forge

```
;Dell iDRAC servers

[x86_host_bmcs]
rno1-m04-d01-02_host_bmc ansible_host=10.180.198.16
rno1-m04-d01-03_host_bmc ansible_host=10.180.198.19
rno1-m04-d01-04_host_bmc ansible_host=10.180.198.20
rno1-m04-d01-05_host_bmc ansible_host=10.180.198.21
rno1-m04-d01-06_host_bmc ansible_host=10.180.198.12
rno1-m04-d01-07_host_bmc ansible_host=10.180.198.11
rno1-m04-d01-08_host_bmc ansible_host=10.180.198.24
rno1-m04-d01-09_host_bmc ansible_host=10.180.198.25
rno1-m04-d01-10_host_bmc ansible_host=10.180.198.26
rno1-m04-d02-02_host_bmc ansible_host=10.180.198.87
rno1-m04-d02-03_host_bmc ansible_host=10.180.198.85
rno1-m04-d02-04_host_bmc ansible_host=10.180.198.84
rno1-m04-d02-05_host_bmc ansible_host=10.180.198.83
rno1-m04-d02-06_host_bmc ansible_host=10.180.198.75
rno1-m04-d02-07_host_bmc ansible_host=10.180.198.82
rno1-m04-d02-08_host_bmc ansible_host=10.180.198.81
rno1-m04-d02-09_host_bmc ansible_host=10.180.198.105
rno1-m04-d02-10_host_bmc ansible_host=10.180.198.80
rno1-m04-d03-02_host_bmc ansible_host=10.180.247.212
rno1-m04-d03-03_host_bmc ansible_host=10.180.247.211
rno1-m04-d03-04_host_bmc ansible_host=10.180.247.210
rno1-m04-d03-05_host_bmc ansible_host=10.180.247.209
rno1-m04-d03-06_host_bmc ansible_host=10.180.247.202
rno1-m04-d03-07_host_bmc ansible_host=10.180.247.208
rno1-m04-d03-08_host_bmc ansible_host=10.180.247.207
rno1-m04-d03-09_host_bmc ansible_host=10.180.247.232
rno1-m04-d03-10_host_bmc ansible_host=10.180.247.231


[x86_host_bmcs:vars]
ansible_user=root
ansible_password=M/uz{HKh@fz6S-%8

[dpus]
;rno1-m04-d01-02 ansible_host= oob_mac=
;rno1-m04-d01-03 ansible_host= oob_mac=
;rno1-m04-d01-04 ansible_host= oob_mac=
;rno1-m04-d01-05 ansible_host= oob_mac=
;rno1-m04-d01-06 ansible_host= oob_mac=
;rno1-m04-d01-07 ansible_host= oob_mac=
;rno1-m04-d01-08 ansible_host= oob_mac=
;rno1-m04-d01-09 ansible_host= oob_mac=
;rno1-m04-d01-10 ansible_host= oob_mac=
;rno1-m04-d02-02 ansible_host= oob_mac=
;rno1-m04-d02-03 ansible_host= oob_mac=
;rno1-m04-d02-04 ansible_host= oob_mac=
;rno1-m04-d02-05 ansible_host= oob_mac=
;rno1-m04-d02-06 ansible_host= oob_mac=
;rno1-m04-d02-07 ansible_host= oob_mac=
;rno1-m04-d02-08 ansible_host= oob_mac=
;rno1-m04-d02-09 ansible_host= oob_mac=
;rno1-m04-d02-10 ansible_host= oob_mac=
;rno1-m04-d03-02 ansible_host= oob_mac=
;rno1-m04-d03-03 ansible_host= oob_mac=
;rno1-m04-d03-04 ansible_host= oob_mac=
;rno1-m04-d03-05 ansible_host= oob_mac=
;rno1-m04-d03-06 ansible_host= oob_mac=
;rno1-m04-d03-07 ansible_host= oob_mac=
;rno1-m04-d03-08 ansible_host= oob_mac=
;rno1-m04-d03-09 ansible_host= oob_mac=
;rno1-m04-d03-10 ansible_host= oob_mac=

[dpus:vars]
ansible_user=ubuntu
ansible_password=ubuntu

[dpu_int_bmcs]
;rno1-m04-d01-02_bmc ansible_host= oob_mac=
;rno1-m04-d01-03_bmc ansible_host= oob_mac=
;rno1-m04-d01-04_bmc ansible_host= oob_mac=
;rno1-m04-d01-05_bmc ansible_host= oob_mac=
;rno1-m04-d01-06_bmc ansible_host= oob_mac=
;rno1-m04-d01-07_bmc ansible_host= oob_mac=
;rno1-m04-d01-08_bmc ansible_host= oob_mac=
;rno1-m04-d01-09_bmc ansible_host= oob_mac=
;rno1-m04-d01-10_bmc ansible_host= oob_mac=
;rno1-m04-d02-02_bmc ansible_host= oob_mac=
;rno1-m04-d02-03_bmc ansible_host= oob_mac=
;rno1-m04-d02-04_bmc ansible_host= oob_mac=
;rno1-m04-d02-05_bmc ansible_host= oob_mac=
;rno1-m04-d02-06_bmc ansible_host= oob_mac=
;rno1-m04-d02-07_bmc ansible_host= oob_mac=
;rno1-m04-d02-08_bmc ansible_host= oob_mac=
;rno1-m04-d02-09_bmc ansible_host= oob_mac=
;rno1-m04-d02-10_bmc ansible_host= oob_mac=
;rno1-m04-d03-02_bmc ansible_host= oob_mac=
;rno1-m04-d03-03_bmc ansible_host= oob_mac=
;rno1-m04-d03-04_bmc ansible_host= oob_mac=
;rno1-m04-d03-05_bmc ansible_host= oob_mac=
;rno1-m04-d03-06_bmc ansible_host= oob_mac=
;rno1-m04-d03-07_bmc ansible_host= oob_mac=
;rno1-m04-d03-08_bmc ansible_host= oob_mac=
;rno1-m04-d03-09_bmc ansible_host= oob_mac=
;rno1-m04-d03-10_bmc ansible_host= oob_mac=

[dpu_int_bmcs:vars]
ansible_user=root
ansible_password=M/uz{HKh@fz6S-%8

[all:vars]
ansible_user=ubuntu
ansible_password=ubuntu
ansible_ssh_common_args='-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null'
discovered_interpreter_python="/usr/bin/python3"
```

hosts-integration-controlnodes.forge

```
;Dell iDRAC servers

[x86_host_bmcs]
dpu_int_reno_int_1_host_bmc ansible_host=10.180.248.3
dpu_int_reno_int_2_host_bmc ansible_host=10.180.248.12
dpu_int_reno_int_3_host_bmc ansible_host=10.180.248.19

[dpus]
dpu_int_reno_int_1 ansible_host=10.180.248.5  oob_mac=10:70:fd:18:0f:fa
dpu_int_reno_int_2 ansible_host=10.180.248.13 oob_mac=08:c0:eb:cb:0e:a4
dpu_int_reno_int_3 ansible_host=10.180.248.21 oob_mac=08:c0:eb:cb:0e:04

[dpus:vars]
ansible_user=ubuntu
ansible_password=ubuntu

[dpu_int_bmcs]
dpu_int_reno_int_1_bmc ansible_host=10.180.248.6 bmc_mac=10:70:fd:18:0f:ee
dpu_int_reno_int_2_bmc ansible_host=10.180.248.14 bmc_mac=08:c0:eb:cb:0e:98
dpu_int_reno_int_3_bmc ansible_host=10.180.248.22 bmc_mac=08:c0:eb:cb:0d:f8

[all:vars]
ansible_user=root
ansible_password=M/uz{HKh@fz6S-%8
ansible_ssh_common_args='-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null'
discovered_interpreter_python="/usr/bin/python3"
```
