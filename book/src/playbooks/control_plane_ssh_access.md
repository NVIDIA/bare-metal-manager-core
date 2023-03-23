# Forge Site Controller control plane node SSH access

The Forge site controller is deployed on 3 nodes in any given site using
[NVIDIA Fleet Command](https://www.nvidia.com/en-us/data-center/products/fleet-command/).
Therefore the control plane nodes are provisioned by Fleet Command, and access
to nodes is managed by Fleet Command.

## Site to NGC org mappings

Each Forge site deployment is owned by a specific Fleet Command
organization. The organization name needs to be known to access nodes and
to gain permissions.

We currently use the following NGC organizations for site deployments:

| Site Names         | NGC env   | NGC Org ID     | NGC Org Display Name     |
|--------------------|-----------|----------------|--------------------------|
| `pdx-dev3`         | `staging` |`wdksahew1rqv` | `Forge-Prime-Provider`   |
| `pdx-qa2`          | `staging` |`wdksahew1rqv` | `Forge-Prime-Provider`   |
| `reno-int-lp`      | `staging` |`wdksahew1rqv` | `Forge-Prime-Provider`   |

## <a name="ui"></a> SSHing to a Forge control plane node via web UI

*Note:: You might need admin credentials for this operation. Check the
[permissions](#permissions) section for details*

To SSH to a Forge control plane instance using the FleetCommand web UI:
1. Open the NGC portal (prod or staging dependent on the site), and select the
  NGC org that is used to manage the Forge site
2. Navigate to Fleet Command/Locations, and click on the location you want to
  access. This should e.g. get you to https://fc.stg.ngc.nvidia.com/locations/reno-int-lp
  for the reno integration site.
3. On this page you should see the 3 Forge Control plane nodes. Click the three
  dots next to a control plane node and select "Start Remote Console" to SSH to the node.
  A new browser window with a SSH terminal will open.

## SSHing to a Forge control plane node via the ngc CLI

The ngc CLI can be used to SSH to a control plane node by using the `ngc remote console`
commmand. E.g. the command

```
ngc fleet-command remote console reno-int-lp:rno1-m04-d03-cpu-1  --org wdksahew1rqv
```

will create a SSH connection to the node `rno1-m04-d03-cpu-1` that is used for the
`reno-int-lp` Forge site. You can follow the [UI based steps](#ui) to get access
to the applicable Forge site and node names.

### NGC CLI installation

The ngc CLI can be downloaded from the NGC portal, e.g.
https://stg.ngc.nvidia.com/setup/installers/cli

Note that that there exists a separate CLI for prod and staging environments.
It is likely preferable to install the staging CLI for newest updates.

Once installed, you will need to create an API token using
https://stg.ngc.nvidia.com/setup/api-key

and configure the ngc CLI using

```
ngc config set
```

Note that the NGC organization you select here is the default organization that
will be used for the `ngc fleet-command remote console` command. If it is specified,
you can skip specifying `--org` for concole commands.

Also note that API keys for NGC are separate between `prod` and `staging`, but
there exists no different API keys for organizations within `prod` or `staging`.
You will have at most 2 API keys. Generating a new API key will invalidate the previous
one - so in case you already have obtained an API key for a different use-case,
reuse that one.

After you configured the CLI correctly, your NGC CLI config file should look along:
```
cat ~/.ngc/config
;WARNING - This is a machine generated file.  Do not edit manually.
;WARNING - To update local config settings, see "ngc config set -h"

[CURRENT]
apikey = YOUR_API_KEY
format_type = ascii
org = wdksahew1rqv
org_display_name = Nvidia-forge
command_map = {"apikey": "YOUR_API_KEY", "commands": ["label-set", "log", "apikey", "image", "org", "subnet", "model", "rule", "tenant", "location", "chart", "deployment", "instance", "team", "diag", "allocation", "user", "machine", "registry", "collection", "settings", "fleet-command", "ssh-key", "metric", "tenant-account", "audit", "usage", "forge", "application", "resource", "provider", "instance-type", "ipblock", "secret", "site", "remote", "component", "appconfig"]}
last_upgrade_msg_date = 2023-02-28::17:05:20
```

## Switching to the root user

To get access to the kubernetes tools for managing the Forge site, you will need
to switch from the SSH user to the admin user first.

Use the following steps:
```
su - admin
sudo su
```

The first step will switch to the `admin` user. The second to the `root` user.
Both steps will require knowledge about the admin password that is used for this
node. Ask your team about how to get access to this password.

## <a name="permissions"></a> Getting the necessary Fleet Command permissions for SSH access

In order to SSH to a Forge Site Controller node, a user must have the `Fleet Command Admin`
role in the NGC organization that is used to manage a site via Fleet Command.

### Checking user permissions

User permissions can be checked by switching to the respective NGC org
in the org selection menu on the top right of the NGC portal and navigating to

- For staging: https://org.stg.ngc.nvidia.com/users
- For prod: https://org.ngc.nvidia.com/users

A user should have the "Fleet Command Admin" permission

### Adding missing permissions

If a user is missing the "Fleet Command Admin" permission, an admin of the
organization can use the follow steps to add permissions:
- In the user view, click on the username to edit
- Click "Edit Membership". This should navivate to a page like https://org.stg.ngc.nvidia.com/users/add/$USER_ID
- Select the Organization (e.g. `wdksahew1rqv`)
- Check the `Admin` checkbox in the `Fleet Command` box.
- Click "Add Role".

**Note: This might lead you to a screen where everything is greyed out,
and where the new role might not yet be reflected. Going back to the
Users screen might also not yet show new permissions. This is a NGC UI
limitation. Users will receive an email invite and first have to accept
this email before the new permissions will show up. This even applies if
the user had NGC access before.**


