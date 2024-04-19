# Dashboards

This page provides an overview of all dashboards that Forge offers.

## <a name="edit_note"></a><span style="color:orange">⚠️ A note on editing dashboards</span>

All dashboards linked on this page are editable depending on user permissions.
Viewers however should not save edited dashboards, unless those changes are useful for other dashboard viewers.

Users are free to make local edits in their browser window to dashboards in order to understand metrics more in detail. However in this case the edits should be discarded using the `Discard` button or by simply closing the browser window. The `Save` button should only be used if other users should also observe the changed dashboard behavior.

An alternative to changing dashboards themselves is to use the "Explore" function of Grafana. All graphs on dashboards can be copied into a local "Explore" view by clicking the "Explore" button in the context menu of graphs.

If permanent modifications to dashboards are required, please follow the instructions at [Modifying Dashboards](#modifying_dashboards) for details.

## Thanos Dashboards

Dashboards on Thanos allow to view the metrics exported to Thanos.
For access to Thanos, view [Site Metrics - Thanos access](site_metrics.md#thanos_access).

### State of the World

The Forge [State of the World dashboard](https://ngcobservability-grafana.thanos.nvidiangn.net/d/0nr2HwVSk/forge-state-of-the-world?orgId=1) provides a high level overview about all sites that are managed by Forge. It's purpose is to provide an easy overview over all Forge sites - including showing information which sites might have operational problems.

### Site dashboard

The Forge [Site dashboard](https://ngcobservability-grafana.thanos.nvidiangn.net/d/WzX_VErVk/argo-forge-sites?orgId=1) provides additional details for each site. These details can help in further understanding site behavior - e.g. in case a problem was identified on the [State of the World dashboard](https://ngcobservability-grafana.thanos.nvidiangn.net/d/0nr2HwVSk/forge-state-of-the-world?orgId=1).

### Forge PostgreSQL Patroni

[Forge PostgresSQL Patroni](https://ngcobservability-grafana.thanos.nvidiangn.net/d/rLzu8z_Vk/forge-postgresql-patroni?orgId=1&refresh=1m) shows metrics extracted from Patroni - the Postgres high availability orchestration system that is installed on each Forge site.

### Forge PostgreSQL Database

[Forge PostgreSQL Database](https://ngcobservability-grafana.thanos.nvidiangn.net/d/000000039/forge-postgresql-database?orgId=1&refresh=10s) shows metrics extracted from the Postgres nodes on each site.

### Forge Pod resources (CPU/Memory)

[Pod Resources](https://ngcobservability-grafana.thanos.nvidiangn.net/d/85a562078cdf77779eaa1add43ccec1e/forge-pod-resources-cpu-memory?orgId=1&refresh=5m) provides information collected from kubernetes/kubelet on each control plane node in Forge sites.

### Blackbox Probes

[Blackbox Probes](https://ngcobservability-grafana.thanos.nvidiangn.net/d/xtkCtBkiz4/blackbox-probes?orgId=1&refresh=15m) shows information from the blackbox probe system. This system continuously performs requests against various services installed in Forge sites and measures/visualizes their availability.

### Additional dashboards

Browse [Dashboards](https://ngcobservability-grafana.thanos.nvidiangn.net/dashboards) to view additional dashboards that are available for Forge.

## Site dashboards

The links in this section point to Grafana on the dev3 site. In order to view the metrics for other sites, replace the ID of the site in the URL.

Note that these dashboards are not available for sites which don't allow for incoming traffic - e.g. `tpe01`.

### Forge site

[Forge site](https://grafana-dev3.frg.nvidia.com/d/WzX_VErVk/forge-site?orgId=1) shows similar metrics as the thanos [Site dashboard](https://ngcobservability-grafana.thanos.nvidiangn.net/d/WzX_VErVk/argo-forge-sites?orgId=1). However the dashboards are not in sync, and it is therefore likely the dashboard deployed on the site is missing some information. If you require any information not found on the dashboard, you can copy the thanos query for a certain dashboard into the [Explore](https://grafana-dev3.frg.nvidia.com/explore) panel on Forge sites.

### Hardware-Health - Hardware health metrics

[Hardware health metrics](https://grafana-dev3.frg.nvidia.com/d/carbide-hardware-health-metrics-v1/hardware-health-metrics?orgId=1&refresh=30s) shows hardware related metrics for each Host that is managed by Forge. The metrics are scraped via redfish from BMCs
via the [Hardware Health](https://gitlab-master.nvidia.com/nvmetal/carbide/-/tree/trunk/health) service.

### Hardware-Health - Serial Console Logs

[Serial Console Logs](https://grafana-dev3.frg.nvidia.com/d/f911bc91-c344-4188-b8bb-5d2d0566d53b/serial-console-logs?orgId=1) shows the last lines of serial console output collected for each Host and DPU managed by Forge on a site. The serial console logs are collected
by the [Forge ssh-console service](https://gitlab-master.nvidia.com/nvmetal/ssh-console) and forwarded to the Loki installation on each site.

This dashboard can be useful to understand the state of a Host (e.g. whether it recently rebooted) without having to connect to the BMC of a Host.

### ArgoCD

[ArgoCD](https://grafana-dev3.frg.nvidia.com/d/LCAgc9rWz/argocd?orgId=1) shows ArgoCD (deployment system) metrics.

### Blackbox Probes

[Blackbox Probes](https://grafana-dev3.frg.nvidia.com/d/xtkCtBkiz/blackbox-probes?orgId=1&refresh=10s) shows information from the blackbox probe system. This system continuously performs requests against various services installed in Forge sites and measures/visualizes their availability.

[Forge PostgresSQL Patroni](https://grafana-dev3.frg.nvidia.com/d/rLzu8z_Vk/patroni-dashboard?orgId=1&refresh=1m) shows metrics extracted from Patroni - the Postgres high availability orchestration system that is installed on each Forge site.

### Forge PostgreSQL Database

[Forge PostgreSQL Database](https://grafana-dev3.frg.nvidia.com/d/wGgaPlciz/postgresql?orgId=1&refresh=10s) shows metrics extracted from the Postgres nodes on each site.

### Vault

[Hashicorp Vault](https://grafana-dev3.frg.nvidia.com/d/vaults/hashicorp-vault?orgId=1) shows metrics extracted from Vault.

### Additional dashboards

Browse [Dashboards](https://grafana-dev3.frg.nvidia.com/dashboards) to view additional dashboards that are available for Forge.

## <a name="modifying_dashboards"></a>Modifying Dashboards

The process to edit a dashboard depends on the dashboards. This section provides an overview on how to edit Thanos dashboards and site local dashboards.
Since both sets of dashboards ideally should show the same data, edits to show additional data should be applied to both locations. 

### Modifying Thanos Dashboards

Dashboards on Thanos are modified directly on Thanos. To modify a dashboard on Thanos
- press edit on the dashboard you want to modify
- make the necesary changes
- click "Apply" on the top righ of the dashboard
- Save the dashboard if you are satisfied with the changes

When editing changes, please also follow the following best practices
- Make sure the panels on each page show up in a uniform fashion.
  If all panels of a dashboard had been extended before your edit, they should keep staying extended after the edit.
  If all panels had been collapsed, they should keep staying collapsed.
- If previous metrics are using variables (like `${ClusterName}`), then make sure that newly added metrics use the same variables.
- Thanos dashboards cover multiple sites which run different versions of the Forge control plane. These versions might emit different sets of metrics.
  Dashboards should be compatible with old and new version of metrics. E.g. if a dashboard shows a "gRPC availablitiy metric", and the way we emit gRPC metrics changes between versions, dashboards should show both versions in a single graph.

### Modifying Site Dashboards

Dashboards that are visible on the sites are deployed together with Grafana.
They are stored at [https://gitlab-master.nvidia.com/nvmetal/forged/-/tree/main/bases/forge-dashboards](https://gitlab-master.nvidia.com/nvmetal/forged/-/tree/main/bases/forge-dashboards).

To modify a dashboard on all sites:
1. Try the changes to a dashboard on a single site (e.g. dev3) via a local edit
2. Create a merge request against `forged` to modify the target dashboard
3. Get approval for the merge request and merge it
4. Sync the new dashboard to all sites via argocd. This step should be performed
  by the Forge SRE team in scope of the Forge rollout process.