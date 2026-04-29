# NCX Infra Controller

NCX Infra Controller (NICo) delivers zero-touch lifecycle automation for bare-metal
systems that secures datacenter infrastructure at its foundation.

It is an API-based microservice that provides site-local, zero-trust,
bare-metal lifecycle management with DPU-enforced isolation. NICo automates the complexity
of the bare-metal lifecycle to fast-track building next generation AI Cloud offerings.

## Getting Started

- Go to the [NCX Infra Controller overview](https://docs.nvidia.com/infra-controller/documentation/introduction) to get an overview of NICo architecture and capabilities.
- Or jump to the [Site Setup guide](https://docs.nvidia.com/infra-controller/documentation/getting-started/site-setup) to start setting up your site for NICo.
- Or jump to the [Building Containers guide](https://docs.nvidia.com/infra-controller/documentation/getting-started/building-ni-co-containers) to see an overview for building the containers.
- Check out [Local Development with DevSpace](dev/deployment/devspace/README.md) to run NICo locally with mock systems.

## Bare-Metal Cluster Setup

`helm-prereqs/setup.sh` deploys the full NCX stack onto a bare-metal Kubernetes cluster in three layers:

| Layer | What it installs | Helm release |
|-------|-----------------|--------------|
| **Common services** | MetalLB, cert-manager, Vault, external-secrets, PostgreSQL | via `helmfile` in `helm-prereqs/` |
| **Carbide Core** | NCX Infra Controller (this repo's `helm/` chart) | `carbide` in `forge-system` |
| **Carbide REST** | NCX REST API, Temporal, Keycloak, site-agent | `carbide-rest` + `carbide-rest-site-agent` in `carbide-rest` |

### Prerequisites

- A running Kubernetes cluster with `KUBECONFIG` set
- `helm`, `helmfile`, `kubectl`, `jq` installed
- Images pushed to your container registry

### Quick start

```bash
# 1. Build and push images to your registry
#    Carbide Core image: <your-registry>/nvmetal-carbide:<tag>  (this repo)
#    Carbide REST images: <your-registry>/carbide-rest-api:<tag>, etc.  (ncx-infra-controller-rest)

# 2. Set environment variables
export KUBECONFIG=/path/to/kubeconfig
export REGISTRY_PULL_SECRET=<your-registry-pull-secret-or-ngc-api-key>
export NCX_IMAGE_REGISTRY=<your-registry>        # e.g. my-registry.example.com/ncx
export NCX_CORE_IMAGE_TAG=<carbide-core-tag>     # e.g. v2025.12.30
export NCX_REST_IMAGE_TAG=<carbide-rest-tag>     # e.g. v1.0.4

# 3. Customize site-specific values
#    Edit helm-prereqs/values/ncx-core.yaml:
#      carbide-api.hostname      — your site's external API hostname
#      carbide-api.siteConfig    — network pools, VLAN ranges, IB config, MetalLB VIPs
#    Edit helm-prereqs/values/metallb-config.yaml:
#      IPAddressPool, BGPPeer    — your site's VIP ranges and TOR switch config
#    Edit helm-prereqs/values.yaml:
#      siteName                  — short site identifier

# 4. Point NCX_REPO at ncx-infra-controller-rest (auto-detected if a sibling directory)
export NCX_REPO=/path/to/ncx-infra-controller-rest   # optional

# 5. Run setup — installs common services, Carbide Core, and Carbide REST in order
cd helm-prereqs
./setup.sh        # interactive
./setup.sh -y     # non-interactive (CI/CD)
```

To tear everything down:

```bash
cd helm-prereqs
./clean.sh
```

See [helm-prereqs/README.md](helm-prereqs/README.md) for the full reference: PKI architecture, PostgreSQL setup, phase-by-phase description, secrets reference, and troubleshooting.

## Experimental Notice

This software is considered *experimental* and is a preview release. Use at
your own risk in production environments. The software is provided "as is"
without warranties of any kind. Features, APIs, and configurations may change
without notice in future releases. For production deployments, thoroughly test
in non-critical environments first.
