# Forge onboarding

## Step 1: Get to know Forge as a user (tenant)

1. Read the Forge tenant documentation at [https://nvmetal.gitlab-master-pages.nvidia.com/forge-docs/user-guide/latest/index.html](https://nvmetal.gitlab-master-pages.nvidia.com/forge-docs/user-guide/latest/index.html)
2. Get access to the "Forge-Tenant-Dev" Org on [https://stg.ngc.nvidia.com](https://stg.ngc.nvidia.com/). Ask a team-member to invite you to this org.
3. Browse existing VPCs on [https://forge.stg.ngc.nvidia.com/vpcs](https://forge.stg.ngc.nvidia.com/vpcs)
4. Create your own VPC with the name `$youruserid-onboarding-vpc`. The name that includes your user alias will help with locating and findings the VPC and other objects later on.
5. Create your own subnet within the VPC with the name `$youruserid-onboarding-subnet`. Use a `/29` prefix length if you plan to create 2 instances, or a `/30` prefix length if you just want to test creating a single instance. Observe the subnet state move from Provisioning to Ready
6. Create a SSH keygroup. Use the name `$youruserid-onboarding-keygroup`. Add a SSH key to it. Sync it with the site dev3.
7. Create an instance within the VPC that uses the newly created subnet. You can use a predefined operating system like `forge-tenant-dev-test-ubuntu-dell` (ssh password will be `Welcome123`).
8. Use the Forge serial over lan console in combination with the SSH key you created to view the instance installing and booting.
9. Once the boot is complete, use regular ssh to connect to the instance. You can find the IP address of your instance in the instance details on the web UI. You will need to use a SSH jumphost to access hosts in dev3 as described in [Jump hosts required to access the Forge control plane servers](sites/control_plane_ssh_access.md#jump-hosts-required-to-access-the-forge-control-plane-servers)

## Step 2: Inspect what happens behind the scenes (For engineers)

1. Use forge-admin CLI to inspect the state of the dev3 site. Check the instructions in the [forge-admin-cli playbook](sites/forge_admin_cli.md). Try to retrieve the following information:
    1. Which VPCs exist?
    2. Which subnets exist?
    3. Which instances exist?
    4. Which machines exist? What is their state?
2. Locate the resources you created in forge-admin-cli. Inspect the state transitions for all them. E.g. to view the state transitions that the Machine that was used to create the instance, use `forge-admin-cli machine show --machine=$machineid`. You can find the machine-id using `forge-admin-cli instance show —instance=$instanceid`
3. Try to identify the state transitions for your subnet and machine on the [Forge dashboard](https://ngcobservability-grafana.thanos.nvidiangn.net/d/WzX_VErVk/argo-forge-sites?orgId=1&var-ClusterName=dev03. You need access to the DL `grafana-ngcobservability-viewer`. Please don’t edit/modify the dashboard at this point in time. If Grafana asks you whether to save anything press cancel.
4. Search for logs that are related to your Machine state transitions. To do that, log into [https://grafana-dev3.frg.nvidia.com/explore](https://grafana-dev3.frg.nvidia.com/explore). Use a query like `{k8s_container_name="carbide-api"} |= "fm100htm5bvj68vrlq3ilueif9nv1s5stpmo9et96s5p60l382a1qonnh4g"` (replace the machine ID with the ID of the Machine that powers your instance).
5. Inspect the state of the DPU that is providing network virtualization for your instance:
    1. Using forge-admin-cli, locate the IP of the associated DPU. You can use `forge-admin-cli managed-host show` for this.
    2. SSH to the DPU using the instructions on the [DPU SSH Access Playbook](sites/dpu_ssh_access.md)
    3. Search for the `forge-dpu-agent` process, which updates the DPU configuration based on requests of the carbide-api control-plane server.
    5. Inspect the logs of the forge-dpu-agent process using `journalctl -u forge-dpu-agent.service`. You should be able to observe the dpu-agent applying new configurations at the time your instance was created.
    6. Inspect the status reports that the DPU is periodically sending to carbide-api. You can check the last submitted report using forge-admin-cli machine network status. 
6. Inspect the state of the site controller database for the objects you created:
    1. Get access to the dev3 site controller node. See [Control Plane SSH Access](sites/control_plane_ssh_access.md)
    2. Execute `kubectl exec -i -t -n postgres forge-pg-cluster-0 -- /usr/bin/psql -U postgres forge_system_carbide`
    3. Execute the following queries to observe basic information around the objects you created:
        1. `select * from vpcs where id = 'your_vpc_id';`
        2. `select * from network_segments where id = 'your_subnet_id';`
        3. `select * from instances where id = 'your_instance_id'; `
        4. `select m.* from machines m JOIN instances i ON m.id = i.machine_id WHERE i.id = 'your_instance_id';`

## Step 3: Tear down all resources in reverse order

1. Delete your instance in the forge-cloud.
    1. While the instance is getting deleted, inspect the logs of forge-dpu-agent and the state history in forge-admin-cli.
    2. Continue monitoring the machine state. Even after the Instance is deleted, the Machine is transition through various cleanup states.
2. Delete your ssh keygroup in forge-cloud
3. Delete your subnet in forge-cloud
    1. While the subnet is deleted, inspect the state history in forge-admin-cli
4. Delete your VPC in forge-cloud
