# Infiniband Runbook

## Motivation

[Infiniband](https://en.wikipedia.org/wiki/InfiniBand) is a new feature in Forge since the latest release. This runbook describes the steps on infrastructure setup and configuration of Forge to enable Infiniband in a site.

## UFM

### Installation

For the Forge product environment, the HA mode is required.

* Follow the [prerequisites](https://docs.nvidia.com/networking/display/ufmenterpriseqsglatest/installing+ufm+server+software) guidance to install all required packages, including the HA part.
* Follow the [HA installation](https://docs.nvidia.com/networking/display/ufmenterpriseqsglatest/installing+ufm+on+bare+metal+server+-+high+availability+mode) guidance to install the UFM in HA mode.

### Configuration

#### Static configurations

Update the following parameters in `$UFM_HOME/ufm/files/conf/gv.cfg`.

```
…
default_membership = limited
…
randomize_sa_key = true
…
m_key_per_port = true
…
```

Update the following parameters in `$UFM_HOME/ufm/files/conf/opensm/opensm.conf`.

```
…
m_key_protection_level 2
…
cc_key_enable 2
…
n2n_key_enable 2
…
vs_key_enable 2
…
```

#### Configurations per UFM

And the following configuration should be configured per UFM:

##### sm_key

A random 64bit integer is required for the sm_key, RANDOM environment value is a simple way to generate it as follows.

```
root:/# printf '0x%04x%04x%04x%04x\n' $RANDOM $RANDOM $RANDOM $RANDOM
0x771d2fe77f553d47
```

Update the sm_key in `$UFM_HOME/ufm/files/conf/opensm/opensm.conf` with the generated 64bit integer as follows.

```
…
sm_key 0x771d2fe77f553d47
…
```

##### allowed_sm_list

Get the GUID of openSM from `$UFM_HOME/ufm/files/conf/opensm/opensm.conf` of each UFM in the fabric.

```
…
guid 0x1070fd03001763d4
…
```

Update allowed_sm_guids in `$UFM_HOME/ufm/files/conf/opensm/opensm.conf` as follows.

```
…
allowed_sm_guids 0x1070fd03001763d4,0x966daefffe2ac8d2
…
```

##### User management

Update the password of the admin as follows. The default password of the admin is 123456; and the new password must be:

* Minimum length is 4
* Maximum length is 30, composed of alphanumeric and "_" characters

```
root:/# curl -s -k -XPUT -H "Content-Type: application/json" -u admin:123456 -d '{"password": "45364nnfgd"}' https://172.16.110.44:443/ufmRest/app/users/admin
{
  "name": "admin"
}
```

Generate a token for admin as follows:

```
root:/# curl -s -k -XPOST -u admin:45364nnfgd https://172.16.110.44:443/ufmRest/app/tokens | jq
{
  "access_token": "XlojlA7zgotVegyIEIP5vnw5C7ZYT9",
  "revoked": false,
  "issued_at": 1711608244,
  "expires_in": 315360000,
  "username": "admin"
}
```

After the configuration, restart the UFM HA cluster as follows:

```
root:/# ufm_ha_cluster stop
root:/# ufm_ha_cluster start
```

And then check UFM HA cluster status:

```
root:/# ufm_ha_cluster status
```

## Forge

### Installation

No additional steps are required to enable Infiniband in Forge.

### Configuration

#### UFM Credential

Get the token of the admin user in UFM in above step, or get it again by following the rest api (the password of the admin user is required to get the token):

```
root:/# curl -s -k -XGET -u admin:45364nnfgd https://172.16.110.44:443/ufmRest/app/tokens | jq
[
  {
    "access_token": "XlojlA7zgotVegyIEIP5vnw5C7ZYT9",
    "revoked": false,
    "issued_at": 1711609276,
    "expires_in": 315360000,
    "username": "admin"
  }
]
```

Create the credential for UFM client in Forge by forge-admin-cli as follows:

```
root:/# forge-admin-cli credential add-ufm --url=https://<address:port> --token=<access_token>
```

#### carbide-api-site-config

Update the configmap `forge-system/carbide-api-site-config-files` to define the pkey range as follows.

Infiniband typically expresses `Pkeys` in hex; the available range is `“0x0 ~ 0x7FFF”`.

```
…
[pools.pkey]
type = "integer"
ranges = [{ start = "200", end = "500" }]
…
```

**NOTES**: The Forge will generate pkey for all partitions that are managed by Forge; please make sure the range does not conflict with existing pkey in UFM if any.

Update the configmap `forge-system/carbide-api-site-config-files` to enable Infiniband features as follows:

```
…
[ib_config]
enabled = true
…
```

To enable the monitor of IB, update the the configmap `forge-system/carbide-api-site-config-files`  as follows:

```
…
[ib_fabric_monitor]
enabled = true
…
```

#### Restart carbide-api

Restart carbide-api to enable Infiniband in site-controller.

### Rollback

Update the configmap forge-system/carbide-api-site-config-files to disable Infiniband features as follows:

```
…
[ib_config]
enabled = false
…
```

Restart carbide-api to disable Infiniband in site-controller.

## FAQ

### Where’s the UFM home directory?

The default home directory is `/opt/ufm`.

### How to check UFM connection?

There is a debug tools for QA/SRE to check the address/token of UFM:

```
root@host-client:/$ kubectl apply -f https://bit.ly/debug-console
root@host-client:/$ kubectl exec -it debug-console -- /bin/bash
root@host-worker:/# export UFM_ADDRESS=https://<ufm address>
root@host-worker:/# export UFM_TOKEN=<ufm token>
root@host-worker:/# ufmctl list
IGNORING SERVER CERT, Please ensure that I am removed to actually validate TLS.
Name           Pkey      IPoIB     MTU       Rate      Level
api_pkey_0x5   0x5       true      2         2.5       0
api_pkey_0x6   0x6       true      2         2.5       0
management     0x7fff    true      2         2.5       0
```

The default partition (`management/0x7fff`) will include all available ports in the fabric; use the `view` sub-command to list all available ports as follows.

```
root@host-worker:/# ufmctl view --pkey 0x7fff
Name           : management
Pkey           : 0x7fff
IPoIB          : true
MTU            : 2
Rate Limit     : 2.5
Service Level  : 0
Ports          :
    GUID                ParentGUID          PortType  SystemID            LID       LogState  Name                SystemName
    1070fd0300bd494c    -                   pf        1070fd0300bd494c    3         Active    1070fd0300bd494c_1  localhost ibp202s0f0
    1070fd0300bd588d    -                   pf        1070fd0300bd588c    10        Active    1070fd0300bd588d_2  localhost ibp202s0f0
    1070fd0300bd494d    -                   pf        1070fd0300bd494c    9         Active    1070fd0300bd494d_2  localhost ibp202s0f0
    b83fd20300485b2e    -                   pf        b83fd20300485b2e    1         Active    b83fd20300485b2e_1  PDX01-M01-H19-UFM-storage-01
    1070fd0300bd5cec    -                   pf        1070fd0300bd5cec    5         Active    1070fd0300bd5cec_1  localhost ibp202s0f0
    1070fd0300bd5ced    -                   pf        1070fd0300bd5cec    8         Active    1070fd0300bd5ced_2  localhost ibp202s0f0
    1070fd0300bd588c    -                   pf        1070fd0300bd588c    7         Active    1070fd0300bd588c_1  localhost ibp202s0f0
```

### How to check whether the token was updated in Forge?

After configuring UFM credentials in Forge, using the following commands to check whether the token was updated in Forge accordingly.

```
kubectl exec -it vault-0 -n vault -- /bin/sh
vault kv get -field=UsernamePassword --tls-skip-verify secrets/ufm/default/auth
```

SRE can also check the InfiniBand fabric monitor metrics emitted by Carbide to determine whether carbide can reach UFM. E.g. the following graph shows a scenario where

* First carbide could not connect to UFM to invalid credentials
* Fixing the credentials provided access and lead UFM metrics (version number) to be emitted

![alt text](../images/ib_ufm_ver.png)

### How to check the log of UFM?

Check the log of rest api from Forge/carbide:

```
root:/# tail $UFM_HOME/files/log/rest_api.log
2024-03-28 07:42:02.954 rest_api INFO    user: ufmsystem, url: (http://127.0.0.1:8000/app/ufm_version/), method: (GET)
2024-03-28 07:42:22.955 rest_api INFO    user: ufmsystem, url: (http://127.0.0.1:8000/app/ufm_version/), method: (GET)
2024-03-28 07:42:42.957 rest_api INFO    user: ufmsystem, url: (http://127.0.0.1:8000/app/ufm_version/), method: (GET)
2024-03-28 07:43:02.960 rest_api INFO    user: ufmsystem, url: (http://127.0.0.1:8000/app/ufm_version/), method: (GET)
2024-03-28 07:43:22.959 rest_api INFO    user: ufmsystem, url: (http://127.0.0.1:8000/app/ufm_version/), method: (GET)
2024-03-28 07:43:42.963 rest_api INFO    user: ufmsystem, url: (http://127.0.0.1:8000/app/ufm_version/), method: (GET)
2024-03-28 07:44:02.960 rest_api INFO    user: ufmsystem, url: (http://127.0.0.1:8000/app/ufm_version/), method: (GET)
2024-03-28 07:44:22.963 rest_api INFO    user: ufmsystem, url: (http://127.0.0.1:8000/app/ufm_version/), method: (GET)
2024-03-28 07:44:42.964 rest_api INFO    user: ufmsystem, url: (http://127.0.0.1:8000/app/ufm_version/), method: (GET)
2024-03-28 07:45:02.964 rest_api INFO    user: ufmsystem, url: (http://127.0.0.1:8000/app/ufm_version/), method: (GET)
```

Check the log of UFM:

```
root:/# tail $UFM_HOME/files/log/ufm.log
2024-03-28 07:46:17.742 ufm   INIT    Request Polling Delta Fabric
2024-03-28 07:46:17.746 ufm   INIT    Get Polling Delta Fabric
2024-03-28 07:46:29.189 ufm   INIT    Prometheus Client: Start request for session 0
2024-03-28 07:46:29.190 ufm   INIT    Prometheus Client: Total Processing time = 0.001149
2024-03-28 07:46:29.191 ufm   INIT    handled device stats. (6) 28597.53 devices/sec. (10) 47662.55 ports/sec.
2024-03-28 07:46:47.748 ufm   INIT    Request Polling Delta Fabric
2024-03-28 07:46:47.751 ufm   INIT    Get Polling Delta Fabric
2024-03-28 07:46:59.190 ufm   INIT    Prometheus Client: Start request for session 0
2024-03-28 07:46:59.191 ufm   INIT    Prometheus Client: Total Processing time = 0.001762
2024-03-28 07:46:59.192 ufm   INIT    handled device stats. (6) 25497.29 devices/sec. (10) 42495.48 ports/sec.
```

### How to check the log of IB in Forge?

```
root:/# kubectl logs carbide-api-77f948cd46-974kr -n forge-system -c carbide-api | grep -iF partition
```

### How to update pool.pkey?

Did not support updating pool.pkey after configuration.

## Reference

* [NVIDIA UFM Enterprise Quick Start Guide](https://docs.nvidia.com/networking/display/ufmenterpriseqsglatest)
* [NVIDIA UFM Enterprise REST API](https://docs.nvidia.com/networking/display/ufmenterpriserestapilatest)