# Lab environments

## Required access groups

In order to reach any of IP's in our lab environments you need to be a member of
`forge-dev-ssh-access` ssh groups.

You must first install the latest version of [nvinit](https://confluence.nvidia.com/display/COS/NGC+Security+Engineering+Home#NGCSecurityEngineeringHome-Installation&Usage) and optionally hashicorp vault.

SSH group membership:

First is `forge-dev-ssh-access`.  Make a [dlrequest](https://dlrequest/GroupID/Groups/Properties?identity=MWQyNmFlNTkxZGU4NDIxMjgwNmNmMzIyOWIxMWI5Njh8Z3JvdXA=) Click Join -> Join perpetually


### DUO

In order to use `nvinit` - which will provide ssh credentials - you have
to be enrolled into DUO 2 factor authentication. Since DUO is no longer the
default for other services in the company, you have to file a request for
it.

To request DUO access, visit [http://dlrequest.nvidia.com](http://dlrequest.nvidia.com) then subscribe to group Duo_Users_Request_Access. An NVIDIA employee will reach out to you
about the request and help to get access.

After you are added to the group, enroll in DUO using [https://duo.nvidia.com](https://duo.nvidia.com),
and install the DUO authentication app on your mobile device.

### nvinit

Once authenticated to vault, you use nvinit to request additional principals
Before running the commands below make sure to have `ssh-agent` running.

```
eval $(ssh-agent)
ssh-add -D
```

```
nvinit ssh -user <AD username> -aggregate -passcode <DUO passcode>
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

