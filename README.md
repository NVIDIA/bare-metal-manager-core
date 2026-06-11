# NVIDIA Infra Controller

NVIDIA Infra Controller (NICo) delivers zero-touch lifecycle automation for
bare-metal systems that secures datacenter infrastructure at its foundation.

It is an API-based microservice that provides site-local, zero-trust,
bare-metal lifecycle management with DPU-enforced isolation. NICo automates the complexity
of the bare-metal lifecycle to fast-track building next generation AI Cloud offerings.

## Getting Started

- Go to the [NVIDIA Infra Controller overview](https://docs.nvidia.com/infra-controller/documentation/overview/what-is-nico) to get an overview of NICo architecture and capabilities.
- Or jump to the [Quick Start Guide](https://docs.nvidia.com/infra-controller/documentation/getting-started/quick-start-guide) to start setting up your site for NICo.
- Check out [Local Development with DevSpace](dev/deployment/devspace/README.md) to run NICo locally with mock systems.

## Bare-Metal Cluster Setup

`helm-prereqs/setup.sh` deploys the full NVIDIA Infra Controller stack onto a bare-metal Kubernetes cluster in three layers:

| Layer | What it installs | Helm release |
|-------|-----------------|--------------|
| **Common services** | MetalLB, cert-manager, Vault, external-secrets, PostgreSQL | via `helmfile` in `helm-prereqs/` |
| **NICo Core** | NVIDIA Infra Controller (this repo's `helm/` chart) | `nico` in `nico-system` |
| **NICo REST** | NVIDIA Infra Controller's REST API, Temporal, Keycloak, site-agent | `nico-rest` + `nico-rest-site-agent` in `nico-rest` |

### Prerequisites

- A running Kubernetes cluster with `KUBECONFIG` set
- `helm`, `helmfile`, `kubectl`, `jq` installed
- Images pushed to your container registry

### Quick start

```bash
# 1. Build and push images to your registry
#    NICo Core image: <your-registry>/nvmetal-nico:<tag>  (this repo)
#    NICo REST images: <your-registry>/nico-rest-api:<tag>, etc.

# 2. Set environment variables
export KUBECONFIG=/path/to/kubeconfig
export NICO_IMAGE_REGISTRY=<your-registry>           # e.g. my-registry.example.com/infra-controller
export NICO_CORE_IMAGE_TAG=<nico-core-tag>           # e.g. 2.0.0-pr-58-g38a54a3f
export NICO_REST_IMAGE_TAG=<nico-rest-tag>           # e.g. 2.0.0-pr-58-g38a54a3f
# export REGISTRY_PULL_SECRET=<raw API key>          # optional; raw key for authenticated registries

# 3. Customize site-specific values
#    Edit helm-prereqs/values/nico-core.yaml:
#      nico-api.hostname      — your site's external API hostname
#      nico-api.siteConfig    — network pools, VLAN ranges, IB config, MetalLB VIPs
#    Edit helm-prereqs/values/metallb-config.yaml:
#      IPAddressPool, BGPPeer    — your site's VIP ranges and TOR switch config
#    Edit helm-prereqs/values.yaml:
#      siteName                  — short site identifier

# 4. Run setup — installs common services, NICo Core, and NICo REST in order
cd helm-prereqs
./setup.sh        # interactive — prompts before deploying Core and REST
./setup.sh -y     # non-interactive — deploys everything (CI/CD)
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
