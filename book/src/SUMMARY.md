# NVIDIA Bare Metal Manager

- [Introduction](README.md)
- [Hardware Compatbility List (WIP)](HCL.md)
- [Release Notes](release-notes.md)
- [FAQs](faqs.md)

# Architecture

- [Overview and components](architecture/overview.md)
- [Redfish Workflow](architecture/redfish_workflow.md)
    - [Redfish Endpoints Reference](architecture/redfish/endpoints_reference.md)
- [Reliable state handling](architecture/state_handling.md)
- [DPU configuration](architecture/dpu_configuration.md)
- [Health checks and health aggregation](architecture/health_aggregation.md)
    - [Health probe IDs](architecture/health/health_probe_ids.md)
    - [Health alert classifications](architecture/health/health_alert_classifications.md)
- [Key Group Synchronization](architecture/key_group_sync.md)
- [Infiniband support]()
    - [NIC and Port selection](architecture/infiniband/nic_selection.md)
- [State Machines]()
    - [Managed Host](architecture/state_machines/managedhost.md)

# Manuals

- [Site Setup](manuals/site-setup.md)
    - [Site Reference Architecture](manuals/site-reference-arch.md)
- [Building BMM Containers](manuals/building_bmm_containers.md)
- [Ingesting Hosts](manuals/ingesting_machines.md)
- [Removing Hosts](manuals/removing_machines.md)
- [Updating Expected Hosts Manifest](manuals/expected_machine_update.md)
- [Updating Hosts](manuals/machine_updates.md)
- [Host Validation](manuals/machine_validation.md)
- [SKU Validation](manuals/sku_validation.md)
- [NVLink Partitioning](manuals/nvlink_partitioning.md)
- [Release Instance API Enhancements](manuals/breakfix_integration.md)
- [Managing VPC Peering](manuals/vpc_peering_management.md)
- [Metrics]()
    - [Core metrics](manuals/metrics/carbide_core_metrics.md)

# Sites and site access

- [carbide-admin-cli access](sites/forge_admin_cli.md)

# Design

- [SPIFFE SVID Design](design/spiffe-svid-sdd.md)

# Development

- [Contributing](contributing.md)
- [Codebase Overview](codebase_overview.md)
- [Bootable Artifacts](bootable_artifacts.md)
- [Bootstrap New Cluster](kubernetes/bootstrap.md)
- [Local Development](development.md)
    - [Running a PXE Client in a VM](development/vm_pxe_client.md)
    - [Re-creating issuer/CA in local dev](development/issuer_ca_recreate.md)
- [Visual Studio Code Remote Development](development/vscode_remote.md)
- [Database]()
    - [Data Model / DB Schema](development/schema.md)
- [DPU/Bluefield](dpu-operations.md)

# Kubernetes

- [TLS](kubernetes/tls.md)

# Playbooks

- [Azure OIDC for NVIDIA Bare Metal Manager-Web UI](playbooks/carbide_web_oauth2.md)
- [Force deleting and rebuilding Forge hosts](playbooks/force_delete.md)
- [Rebooting a machine](playbooks/machine_reboot.md)
- [Instance/Subnet/etc is stuck in a state]()
    - [Overview and general troubleshooting](playbooks/stuck_objects/stuck_objects.md)
    - [Common Mitigations](playbooks/stuck_objects/common_mitigations.md)
    - [Stuck in `WaitingForNetworkConfig` and DPU Health](playbooks/stuck_objects/waiting_for_network_config.md)
    - [Machine stuck in DPU `Reprovisioning`](playbooks/stuck_objects/dpu_reprovisioning.md)
    - [State is stuck in Forge Cloud](playbooks/stuck_objects/stuck_in_forge_cloud.md)
    - [Adding new machines to an existing site](playbooks/stuck_objects/adding_new_machines.md)
    - [Troubleshooting noDpuLogsWarning alerts](playbooks/troubleshooting_noDpuLogsWarning_alerts.md)
- [Debugging Machine]()
    - [Collecting Debug Bundles](playbooks/debugging_machine/debug_bundle.md)
- [InfiniBand setup](playbooks/ib_runbook.md)
- [Hardware](playbooks/hardware/hardware.md)
    - [Desired Firmware Version](desired_firmware.md)
    - [Getting Support](playbooks/hardware/getsupport.md)
    - [OneCLI](playbooks/hardware/onecli.md)

# Glossary

- [Glossary](glossary.md)
