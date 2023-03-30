# Lab environments

## Required access groups

In order to reach any of IP's in our lab environments you need to be a member of
`forge-dev-ssh-access` ssh groups.

You must first install the latest version of [nvinit](https://confluence.nvidia.com/display/COS/NGC+Security+Engineering+Home#NGCSecurityEngineeringHome-Installation&Usage) and optionally hashicorp vault.<br>
If you already have `nvinit` installed, make sure the version is `>=2.1.5`

SSH group membership:

First is `forge-dev-ssh-access`.  Make a [dlrequest](https://dlrequest/GroupID/Groups/Properties?identity=MWQyNmFlNTkxZGU4NDIxMjgwNmNmMzIyOWIxMWI5Njh8Z3JvdXA=) Click Join -> Join perpetually


### nvinit
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

Add the following to your `.ssh/config`:

```
Host sjc4jump 24.51.7.3
  Hostname 24.51.7.3
  Compression yes
  User bouncer
  PubkeyAcceptedKeyTypes=+ssh-rsa-cert-v01@openssh.com

Host renojump 155.130.12.194
  Hostname 155.130.12.194
  Compression yes
  User bouncer
  PubkeyAcceptedKeyTypes=+ssh-rsa-cert-v01@openssh.com  # This is only required if you are running the latest SSH.  OpenSSH deprecated RSA a while ago

Host *.nsv.sjc4.nvmetal.net 10.150.* 10.181.20.* 10.181.21.*
  ProxyJump sjc4jump

Host 10.180.32.* 10.180.222.* 10.180.221.* 10.180.124.*
  ProxyJump renojump
```

**Note**: Jump hosts no longer allow direct ssh access. They should be used as jump hosts only.<br>Example: `ssh -J <win_ad_user>@<dc_jumphost> <os_user>@<host_ip/host_fqdn>`
