This document describes steps required to connect hydrazine controller to the cumulus devices.

### ssh forwarding
If the cumulus devices are behind a jump host, enable ssh forwarding on your local host environment.
For instance, the following ssh forwarding command allows processes running in the local test environment to access 
a cumulus device's NVUE binding port at `192.168.200.12:8765` behind a jump host `worker10.air.nvidia.com` via 
local port 8888. Here we assume that the jump host already has local host's ssh certificate and can be sshed into 
from the local host. 

```bash
ssh -f -N -L :8888:192.168.200.12:8765 cumulus@worker10.air.nvidia.com -p 18604
```

You can test if ssh forwarding is working via

```bash
curl -u "cumulus:cumulus!" https://localhost:8888/cue_v1/revision/empty --insecure
{
  "state": "inactive",
  "transition": {
    "issue": {},
    "progress": ""
  }
}
```

### Hydrazine Controller Accessing Cumulus
At present, hydrazine controller support only single user/pwd for all cumulus devices.
Modify config/manager/manager.yaml in the following section,
```yaml
     ....
       env:
        - name: CUMULUS_USER
          value: "cumulus"
        - name: CUMULUS_PWD
          value: "cumulus!"
        - name: FORTINET_USER
          value: user
        - name: FORTINET_PWD
          value: pwd
        - name: DISABLE_CUMULUS_CERT_VERIFY
          value: "true"
     ....
```
Change CUMULUS_USER, CUMULUS_PWD to corresponding values used by the cumulus devices.
`DISABLE_CUMULUS_CERT_VERIFY` is true or false depending on if the cumulus devices' certificates can be validated.

Then apply this updated hydrazine manifest,
```bash
make manifests
kubectl apply -f config/hydrazine.yaml
```

The following sample DPU CRD is applied to a KinD cluster with ssh forwarding enabled.
```bash
cat <<EOF | kubectl apply -f -
apiVersion: networkfabric.vpc.forge.gitlab-master.nvidia.com/v1alpha1
kind: DPU
metadata:
  name: test-dpu-1
  namespace: hydrazine-system
spec:
  control:
    vendor: cumulus
    managementIP: 172.18.0.1:8888
    identifier: 00:01:02:03:04:05
EOF
dpu.networkfabric.vpc.forge.gitlab-master.nvidia.com/test-dpu-1 created
```
This tells the hydrazine controller to connect to a cumulus device via port `172.18.0.1:8888`. And if all goes well, 
you should see that hydrazine controller is connected to the cumulus device. 
```bash
suw@ubuntu:~/data/go/src/gitlab-master.nvidia.com/vpc$ kubectl get dpu -A
NAMESPACE          NAME         MGMT-IP           MAINTENANCE   STATUS
forge-system   test-dpu-1   172.18.0.1:8888                 True

```
