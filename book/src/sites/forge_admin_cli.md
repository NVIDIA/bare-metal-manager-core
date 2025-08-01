# forge-admin-cli setup

## Docker container
In order to run the container you must authenticate with `nvcr.io` docker registry
there are several pre-requisites that must be met

First, `forge-admin-cli` will need the root certificate that site certificates
are signed with. Currently this can be found here: <https://gitlab-master.nvidia.com/nvmetal/forged/-/tree/main/envs#certificate-authority>.
Copy and paste this into a file on your host (we will assume this is `~/.config/forge/forge-root-ca.pem`
in these instructions). This is a one-time step and shouldn't need to be
revisited unless the root certificate changes.

1. nvinit must be installed
2. You must be a member of the AD group `swngc-forge-admins` - Can request through https://dlrequest
3. Ask in `#swngc-forge-dev` slack channel for an invite to the `nvidian/nvidian-devl` organization in ngc webui
4. Once you accept the invite you should be able to login to `https://ngc.nvidia.com`
5. Follow the directions here - https://docs.nvidia.com/ngc/gpu-cloud/ngc-user-guide/index.html#generating-api-key to generate an api key.
   On the screen where you generate an API key, under "Usage" there are instructions for authenticating with the docker cli
6. Follow the directions for [nvinit user certificates](#nvinit-user-certificates)
7. `docker run -v ~/.nvinit:/root/.nvinit nvcr.io/nvidian/nvforge-devel/forge-admin-cli:latest`

The docker image runs on both x86 and ARM based processors.

To update to the latest version: `docker pull nvcr.io/nvidian/nvforge-devel/forge-admin-cli:latest`

You can substiture `docker run -v ~/.nvinit:/root/.nvinit nvcr.io/nvidian/nvforge-devel/forge-admin-cli:latest`
wherever you see `/forge-admin-cli` in the documentation

## Root certificate setup
*NOTE* If using the docker container you do not need to do this. The root cert is already present in the container

First, `forge-admin-cli` will need the root certificate that site certificates
are signed with. Currently this can be found here: <https://gitlab-master.nvidia.com/nvmetal/forged/-/tree/main/envs#certificate-authority>.
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
    -ttl 12h \
    -vault-role ${VAULT_ROLE} \
    -output-keyfile ${CERT_DIR}/nvinit-user
```

These certs are probably only valid for a few hours, so you may need to
re-run this multiple times per day. Again, feel free to customize the file
paths to your liking, but we'll be assuming they look like the above for these
instructions.

## carbide_api_cli.json config file
*NOTE* If you are using the docker container, this step is not required. The config file and directory structure
are already present in the container.

Run this (or manually substitute the `$HOME` variable). `forge-admin-cli` will look for this config file in that location by default.

```bash
cat > ~/.config/carbide_api_cli.json << EOF
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
forge-admin-cli -c https://api-dev3.frg.nvidia.com/ version
```

The per-environment endpoints are listed here under the "Carbide" column: <https://gitlab-master.nvidia.com/nvmetal/forged/-/tree/main/envs#environments>

# forge-admin-cli access on a Forge cluster

The following steps can be used on a control-plane node of a Forge cluster
to gain access to `forge-admin-cli`:

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
