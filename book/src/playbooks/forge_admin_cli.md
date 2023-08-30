# forge-admin-cli setup

You can use `forge-admin-cli` from any host that has connectivity to the
carbide-api service for a site.

## Root certificate setup

First, `forge-admin-cli` will need the root certificate that site certificates
are signed with. Currently this can be found here: [https://gitlab-master.nvidia.com/nvmetal/forged/-/tree/main/envs#certificate-authority].
Copy and paste this into a file on your host (we will assume this is `~/.config/forge/forge-root-ca.pem`
in these instructions). This is a one-time step and shouldn't need to be
revisited unless the root certificate changes.

## nvinit user certificates

Use this script or adapt it to your own workflow:
```bash
#!/bin/bash

set -eu

# This role path may be different if you are not on the Forge team.
VAULT_ROLE=/pki-k8s-usercert/issue/swngc-forge-admins
CERT_DIR=${HOME}/.nvinit/certs

nvinit x509-user \
    -vault-role ${VAULT_ROLE} \
    -output-keyfile ${CERT_DIR}/nvinit-user
```

These certs are probably only valid for a few hours, so you may need to re-
run this multiple times per day. Again, feel free to customize the file paths
to your liking, but we'll be assuming they look like the above for these
instructions.

## carbide_api_cli.json config file

Run this (or manually substitute the `$HOME` variable). `forge-admin-cli` will look for this config file in that location by default.

```bash
envsubst > ~/.config/carbide_api_cli.json << EOF
{
  "forge_root_ca_path": "$HOME/.config/forge/forge-root-ca.pem",
  "client_key_path": "$HOME/.nvinit/certs/nvinit-user",
  "client_cert_path": "$HOME/.nvinit/certs/nvinit-user.crt"
}
EOF
```

## Usage

With all of that set up, you can now target an individual site with the `-c` option. For example:
```bash
forge-admin-cli -c https://api-demo1.frg.nvidia.com/ version
```

The per-environment endpoints are listed here under the "Carbide" column: [https://gitlab-master.nvidia.com/nvmetal/forged/-/tree/main/envs#environments]

# forge-admin-cli access on a Forge cluster

The following steps can be used on a control-plane node of a Forge cluster
to gain access to `forge-admin_cli`:

1. Enter the api-server POD, which also contains copy of `forge-admin-cli`:
```
kubectl exec -ti deploy/carbide-api -n forge-system -- /bin/bash
```

2. Move to forge-admin-cli directory (optional)
```
cd /opt/carbide/
```

3. Utilize the admin-cli
```
/opt/carbide/forge-admin-cli -c https://127.0.0.1:1079 machine show --all
```

Note that you can either use a loopback address (`127.0.0.1`) inside the POD,
or use the cluster-ip of the service, which can be obtained by

```
kubectl get services -n forge-system
```

Output:
```
carbide-api    NodePort    10.104.18.37     <none>        1079:1079/TCP       28d
```

Therefore also the following invocation is possible:
```
/opt/carbide/forge-admin-cli -c https://10.104.18.37:1079 machine show --all
```

**Note:** Once forge site controller migrates to using TLS, you might need
to use `https:` as schema