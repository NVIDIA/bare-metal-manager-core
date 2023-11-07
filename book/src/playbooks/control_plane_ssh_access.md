# Forge Site Controller control plane node SSH access

The Forge site controller is deployed on 3 nodes in any given site using
[NVIDIA Fleet Command](https://www.nvidia.com/en-us/data-center/products/fleet-command/).
Therefore the control plane nodes are provisioned by Fleet Command, and access
to nodes is managed by Fleet Command.

At this time there exist 2 different mechanism to access control plane nodes
provisioned by FleetCommand.
1. [nvssh based access](#nvinit_access)
2. [FleetCommand remote ssh access](#fc_access)

This playback explains both approaches.

## 1. <a name="nvinit_access"></a> nvssh based access

Accessing control plane nodes via plain ssh, while obtaining credentials via
`nvinit`, is the easiest approach to access a Forge control plane node.

If you have `nvinit` already installed, you can simply invoke
```
nvinit ssh -user `whoami`
```
to obtain credentials and afterwards directly `ssh` onto a control plane node.
If your local user does not match your nvidia login, replace the invocation of
`whoami` with your actual login.

## Obtaining the IPs of Forge Control plane nodes

IPs for Forge control plane nodes can be looked up in the FleetCommand web UI
using the following steps:
1. Log into NGC staging or production environment and select the required NGC
  Organization ID for the site you want to interact with
  - All our staging sites so far use the organization `Forge-Prime-Provider`
  - Our production sites use the organization `???`
2. Open the FleetCommand locations page in NGC:
  - Staging: https://fc.stg.ngc.nvidia.com/locations
  - Prod: https://fc.ngc.nvidia.com/locations
3. Click one the location you want to interact with, e.g. `pdx-dev3`
4. In the box of a control plane node - e.g. `pdx01-m01-h16-cpu-1`, click on `Details`
5. Copy the IPv4 address in `IP Addresses`. This will be the IP address you can
  `ssh` to for control plane access.

### Jump hosts required to access the Forge control plane servers

In order to ssh to a Forge control plane node, you will need to specify a jump
host via the `ssh -J` parameter. The following jump hosts can be used by adding
them to `.ssh/config`:

```
Host sjc4jump 24.51.7.3
  Hostname 24.51.7.3
  Compression yes
  PubkeyAcceptedKeyTypes=+ssh-rsa-cert-v01@openssh.com

Host renojump 155.130.12.194 
  Hostname 155.130.12.194
  Compression yes
  PubkeyAcceptedKeyTypes=+ssh-rsa-cert-v01@openssh.com  # This is only required if you are running the latest SSH. OpenSSH deprecated RSA a while ago

Host pdxjump 10.217.0.131
  Hostname 10.217.0.131
  Compression yes
  PubkeyAcceptedKeyTypes=+ssh-rsa-cert-v01@openssh.com

# Azure Colo jump hosts from https://gitlab-master.nvidia.com/nsvmc/mc-ssh-configs

# For az01
Host wus-jb-admin01 10.45.32.84
  Hostname 10.45.32.84
  Compression yes
  PubkeyAcceptedKeyTypes=+ssh-rsa-cert-v01@openssh.com

# For az20
Host sdc-jb-admin01 10.45.33.84
  Hostname 10.45.33.84
  Compression yes
  PubkeyAcceptedKeyTypes=+ssh-rsa-cert-v01@openssh.com

Host *
  StrictHostKeyChecking no
  ServerAliveInterval 30
  ServerAliveCountMax 2
  ForwardAgent yes
  LogLevel QUIET

# You can specify that the jump host is automatically applied for certain IPs
# using sections like this.
Host *.nsv.sjc4.nvmetal.net 10.150.* 10.181.20.* 10.181.21.*
  ProxyJump sjc4jump

Host 10.180.32.* 10.180.222.* 10.180.221.* 10.180.124.*
  ProxyJump renojump
```

All 3 jump hosts will work for all Nvidia owned Forge sites. However you might
obtain better performance by specifying a jump host in the same datacenter as
the Forge site.

**Note**: Jump hosts no longer allow direct ssh access. They should be used as jump hosts only.<br>Example: `ssh -J <win_ad_user>@<dc_jumphost> <os_user>@<host_ip/host_fqdn>`

### Putting it all together

After you obtained the IP for a Control Plane node and added jump hosts, you can
start sshing to the node with a command like:
```
ssh -J renojump 10.217.4.197
```

This will get you to the `pdx-dev3` environment.
After you are on the control plane node, you will need to switch to the `root user` 
by executing
```
sudo su
```
No password should be required for this.

### `~/.ssh/config` entries for commonly used dev sites

If you want to avoid looking up the IPs for control plane nodes for each access,
you can store them along a suitable host name in your ssh config file. E.g. add
this to `~/.ssh/config`:

```
Host renolp
  Hostname 10.180.248.29
  ProxyJump renojump

Host qa2
  Hostname 10.217.5.197
  ProxyJump renojump

Host dev3
  Hostname 10.217.4.197
  ProxyJump renojump

Host pdx01
  Hostname 10.217.6.197
  ProxyJump pdxjump

Host az01
  Hostname 10.45.2.5
  ProxyJump wus-jb-admin01

Host az20
  Hostname 10.45.10.3
  ProxyJump sdc-jb-admin01

Host demo1
  Hostname 10.217.5.193
  ProxyJump renojump

Host demo2
  Hostname 10.217.5.195
  ProxyJump renojump
```

Then you can simply execute
```
ssh dev3
```

to reach the site. If the IP ever changes, you will need to update your config file.

### Requirements for nvinit based ssh access

Forge control plane nodes must have the `nvssh-enabler` DaemonSet deployed
in order to support `nvinit` based access. If this DaemonSet is not available,
you have to fall back to FleetCommand remote ssh access.

### Required access groups

In order to reach any of IP's in our lab environments you need to be a member of
`forge-dev-ssh-access` ssh groups.

Make a [dlrequest](https://dlrequest/GroupID/Groups/Properties?identity=MWQyNmFlNTkxZGU4NDIxMjgwNmNmMzIyOWIxMWI5Njh8Z3JvdXA=) Click Join -> Join perpetually

### nvinit installation

See [nvinit](https://confluence.nvidia.com/display/COS/NGC+Security+Engineering+Home#NGCSecurityEngineeringHome-Installation&Usage).

**Windows users**: See [this](https://gitlab-master.nvidia.com/ngcsecurity/nvinit/-/blob/master/docs/windows.md) document and make sure that your `ssh-agent` service is not in a `disabled` state

**NBU users**: Pulse Secure VPN might have issues with access to remote servers. Use Cisco AnyConnect VPN.


Once authenticated to vault, you use nvinit to request additional principals
Before running the commands below make sure to have `ssh-agent` running.

```
eval $(ssh-agent)
ssh-add -D
```

```
nvinit ssh -user <AD username>
```

## 2. <a name="fc_access"></a> FleetCommand remote ssh access

### Site to NGC org mappings

Each Forge site deployment is owned by a specific Fleet Command
organization. The organization name needs to be known to access nodes and
to gain permissions.

We currently use the following NGC organizations for site deployments:

| Site Names         | NGC env   | NGC Org ID     | NGC Org Display Name     |
|--------------------|-----------|----------------|--------------------------|
| `pdx-dev3`         | `staging` |`wdksahew1rqv`  | `Forge-Prime-Provider`   |
| `pdx-qa2`          | `staging` |`wdksahew1rqv`  | `Forge-Prime-Provider`   |
| `reno-int-lp`      | `staging` |`wdksahew1rqv`  | `Forge-Prime-Provider`   |

### <a name="ui"></a> SSHing to a Forge control plane node via web UI

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

### SSHing to a Forge control plane node via the ngc CLI

The ngc CLI can be used to SSH to a control plane node by using the
`ngc remote console` commmand. E.g. the command

```
ngc fleet-command remote console reno-int-lp:rno1-m04-d03-cpu-1  --org wdksahew1rqv
```

will create a SSH connection to the node `rno1-m04-d03-cpu-1` that is used for the
`reno-int-lp` Forge site. You can follow the [UI based steps](#ui) to get access
to the applicable Forge site and node names.

#### NGC CLI installation

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

### Switching to the root user

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

### <a name="permissions"></a> Getting the necessary Fleet Command permissions for SSH access

In order to SSH to a Forge Site Controller node, a user must have the `Fleet Command Admin`
role in the NGC organization that is used to manage a site via Fleet Command.

#### Checking user permissions

User permissions can be checked by switching to the respective NGC org
in the org selection menu on the top right of the NGC portal and navigating to

- For staging: https://org.stg.ngc.nvidia.com/users
- For prod: https://org.ngc.nvidia.com/users

A user should have the "Fleet Command Admin" permission

#### Adding missing permissions

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
