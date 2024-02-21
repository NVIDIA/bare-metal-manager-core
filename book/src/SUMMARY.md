# NVIDIA Forge

- [Introduction](README.md)
- [Onboarding](onboarding.md)
- [Architecture](architecture.md)
- [Workflow](workflow.md)
- [Usage]()

# Architecture

- [Key Group Synchronization](architecture/key_group_sync.md)
- [Infiniband support]()
  - [NIC and Port selection](architecture/infiniband/nic_selection.md)
- [State Machines]()
  - [ManagedHost](architecture/state_machines/managedhost.md)

# Sites and site access

- [Forge Site Controller control plane node SSH access](sites/control_plane_ssh_access.md)
- [Configuring kubernetes for site access](sites/remote_kubernetes.md)
- [forge-admin-cli access](sites/forge_admin_cli.md)
- [DPU SSH access](sites/dpu_ssh_access.md)

# Components

- [gRPC API]()
- [Boot Controller]()
- [DHCP Service]()
- [DNS Service]()
- [BMC Proxy]()
- [Network Virtualization (Hydrazine)]()

# Development

- [Contributing](contributing.md)
- [Codebase Overview](codebase_overview.md)
- [Bootable Artifacts](bootable_artifacts.md)
- [Bootstrap New Cluster](kubernetes/bootstrap.md)
- [Local Development](development.md)
  - [Kubernetes (no longer works)](kubernetes/development.md)
  - [Docker (works but deprecated)](docker/development.md)
  - [Running a PXE Client in a VM](development/vm_pxe_client.md)
- [Visual Studio Code Remote Development](development/vscode_remote.md)
- [Data Model / DB Schema](development/schema.md)
- [DPU/Bluefield](dpu-operations.md)
- [Baby Forge](babyforge.md)

# Kubernetes

- [Helm](kubernetes/helm.md)
- [TLS](kubernetes/tls.md)

# Playbooks

- [Azure OIDC for a Forge Site](playbooks/azure_oidc.md)
- [Force deleting and rebuilding Forge hosts](playbooks/force_delete.md)
- [Rebooting a machine](playbooks/machine_reboot.md)
- [Discovering Machines](playbooks/machine_discovery.md)
- [Cleaning up the Gitlab Runner in CI when it runs out of disk space](playbooks/gitlab_runner_disk_cleanup.md)
- [kubectl cheat sheet for Forge deployments](playbooks/kubectl.md)
- [Instance/Subnet/etc is stuck in a state](playbooks/stuck_objects.md)

# NVMesh

- [API docs](static/nvmesh/index.html)

# Glossary

- [Glossary](glossary.md)

# Archives

- [Legacy development environment](archives/legacy-development.md)
