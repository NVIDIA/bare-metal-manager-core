# NVIDIA Forge

- [Introduction](README.md)
- [Onboarding](onboarding.md)
- [Architecture](architecture.md)
- [Usage]()

# Architecture

- [DPU configuration](architecture/dpu_configuration.md)
- [Key Group Synchronization](architecture/key_group_sync.md)
- [Infiniband support]()
  - [NIC and Port selection](architecture/infiniband/nic_selection.md)
- [State Machines]()
  - [ManagedHost](architecture/state_machines/managedhost.md)

# Sites and site access

- [Forge Site Controller control plane node SSH access](sites/control_plane_ssh_access.md)
- [Configuring kubernetes for site access](sites/remote_kubernetes.md)
- [Remote Site Access Using an ssh Socks Proxy](sites/remote_access.md)
- [forge-admin-cli access](sites/forge_admin_cli.md)
- [DPU SSH access](sites/dpu_ssh_access.md)

# Observability (Metrics & Logs)

- [Site metrics](observability/site_metrics.md)
- [Site logs](observability/site_logs.md)
- [Dashboards](observability/dashboards.md)

# Components

- [gRPC API]()
- [Boot Controller]()
- [DHCP Service]()
- [DNS Service]()
- [BMC Proxy]()
- [Desired Firmware Version](desired_firmware.md)

# Development

- [Contributing](contributing.md)
- [Codebase Overview](codebase_overview.md)
- [Bootable Artifacts](bootable_artifacts.md)
- [Bootstrap New Cluster](kubernetes/bootstrap.md)
- [Local Development](development.md)
  - [Kubernetes (no longer works)](kubernetes/development.md)
  - [Docker (works but deprecated)](docker/development.md)
  - [Running a PXE Client in a VM](development/vm_pxe_client.md)
  - [Re-creating issuer/CA in local dev](development/issuer_ca_recreate.md)
- [Visual Studio Code Remote Development](development/vscode_remote.md)
- [Database]()
  - [Data Model / DB Schema](development/schema.md)
  - [Local Playground](development/database_local_playground.md)
  - [Backup/Restore Management](development/database_backup_and_restore.md)
- [DPU/Bluefield](dpu-operations.md)
- [Baby Forge](babyforge.md)
- [Hot Fix Process](hotfix.md)

# Testing

- [Scheduled Testing](testing/scheduled.md)
- [Pre-Merge Testing](testing/pre-merge.md)

# Kubernetes

- [Helm](kubernetes/helm.md)
- [TLS](kubernetes/tls.md)

# Playbooks

- [Update CI/CD SSA secret for nSpect Scans](playbooks/update-ssa-key.md)
- [Azure OIDC for a Forge Site](playbooks/azure_oidc.md)
- [Azure OIDC for Carbide-Web UI](playbooks/carbide_web_oauth2.md)
- [Force deleting and rebuilding Forge hosts](playbooks/force_delete.md)
- [Rebooting a machine](playbooks/machine_reboot.md)
- [Discovering Machines](playbooks/machine_discovery.md)
- [Cleaning up the Gitlab Runner in CI when it runs out of disk space](playbooks/gitlab_runner_disk_cleanup.md)
- [kubectl cheat sheet for Forge deployments](playbooks/kubectl.md)
- [Instance/Subnet/etc is stuck in a state]()
  - [Overview and general troubleshooting](playbooks/stuck_objects/stuck_objects.md)
  - [Common Mitigations](playbooks/stuck_objects/common_mitigations.md)
  - [Stuck in `WaitingForNetworkConfig` and DPU Health](playbooks/stuck_objects/waiting_for_network_config.md)
  - [Machine stuck in DPU `Reprovisioning`](playbooks/stuck_objects/dpu_reprovisioning.md)
  - [State is stuck in Forge Cloud](playbooks/stuck_objects/stuck_in_forge_cloud.md)
  - [Adding new machines to an existing site](playbooks/stuck_objects/adding_new_machines.md)
  - [Troubleshooting noDpuLogsWarning alerts](playbooks/troubleshooting_noDpuLogsWarning_alerts.md)
- [InfiniBand setup](playbooks/ib_runbook.md)
- [Updating Expected Machines Manifest](playbooks/em_update.md)

# NVMesh

- [API docs](static/nvmesh/index.html)

# Machine Validation

- [Machine Validation](machine_validation/machine_validation.md)
- [SKU Validation](machine_validation/sku_validation.md)

# Glossary

- [Glossary](glossary.md)

# Archives

- [Legacy development environment](archives/legacy-development.md)
