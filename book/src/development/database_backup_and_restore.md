# Managing Forge Database Backups

*Postgres* backups for *Forge* are managed by the [postgres-operator](https://github.com/zalando/postgres-operator) component, which is used to manage all aspects of the `forge-pg-cluster` database cluster. Behind the scenes, [wal-g](https://github.com/wal-g/wal-g) is used to manage the backup & restore operations, which is what this document focuses on (*note: it could also use [wal-e](https://github.com/wal-e/wal-e), but `wal-e` is deprecated in favor of `wal-g`, so we explicitly enable `wal-g`*).

Out of the box, `wal-g` has support for storing to S3, and since *nvidia* has its own internal blob storage with an S3 interface (thanks to [SwiftStack](https://techcrunch.com/2020/03/05/nvidia-acquires-data-storage-and-management-platform-swiftstack/)), we use that, and manage our account(s) + quota via the [nvidia Core Storage Portal](https://cssportal.sre.nsv.nvidia.com:4443/). You should already have access to look at our accounts, view credentials, etc.

## Credentials

There's a good chance if you're here, you're probably going to need (or are looking for) credentials to be able to read/write/manage storage, so I'm covering that first. All you need to do is go to the [nvidia Core Storage Portal](https://cssportal.sre.nsv.nvidia.com:4443/) and click **Login**.

![Core Storage Portal Login](../static/db_backups_core_storage_portal_login.png)

Once you're logged in, you'll be brought to a service status page. Now click **Manage My Storage**.

![Core Storage Service Status](../static/db_backups_core_storage_portal_status.png)

From there, the **My Storage Details** page will open, at which point you will see
- All clusters we have storage in.
- The username for each cluster.
- The quota for each cluster (and how much is used).

![Core Storage Details](../static/db_backups_core_storage_portal_details.png)

From there, click the "i" (info) icon next to the **User**, which will bring up the **Access Credentials** pane, which also includes snippets for how to use it with various CLI tools (such as `s5cmd`, `awscli`, etc):

![Core Storage Access Information](../static/db_backups_core_storage_access.png)

Tada! You now know how to get credentials for a given cluster and storage namespace (as well as the endpoint to use, *e.g. https://pkss.s8k.io*) Note that, within a storage namespace are buckets. As in, you connect to a cluster with given credentials, and those credentials allow you to access the namespace in that cluster. From there is where you add buckets, read/write files, etc. I think it's probably obvious, but it's probably good to clarify the terminology.

## Using s5cmd

Working with the data in PBSS is simple -- I just use an S3-compatible CLI tool, specifically [s5cmd](https://github.com/peak/s5cmd) (but you could also use `awscli` or `s3cmd`).

**First, install `s5cmd`.**

This assumes you have a working `go` installation, which I think we all do at this point. You could also download builds, but I just do `go install` and point it at the latest version (or whatever is referenced by their `README.md`):

```
go install github.com/peak/s5cmd/v2@master
```

**Next, set some environment variables.**

You can either pass these via the command line, or you can export them in your `~/.bashrc` or whatever you use. Yeah yeah sorry I'm using bash as the reference.

```
# This is also known as the Storage Space User Name
# or S3 Access Name within the Core Storage Portal
export AWS_ACCESS_KEY_ID="team-forge"

# This is also known as the Storage Space User Password
# or S3 Secret Key within the Core Storage Portal.
export AWS_SECRET_ACCESS_KEY="*****"

# This is also known as the Cluster Endpoint within
# the Core Storage Portal.
export S3_ENDPOINT_URL="https://pbss.s8k.io"
```

The Core Storage Portal Access Credentials pane also has tabs with snippets to explain how to use every tool -- it's really nice!

Make sure it works by listing everything in the `forge-pg-cluster` bucket (or any bucket you want):

```
s5cmd ls s3://forge-pg-cluster/*
```

## Configuration

All configuration is managed via the [nvmetal/forged](https://gitlab-master.nvidia.com/nvmetal/forged) repository.

To configure backups (and restores), `postgres-operator` has two configuration variables that need to be set in its [values.yaml](https://gitlab-master.nvidia.com/nvmetal/forged/-/blob/main/bases/postgres-operator/values.yaml):
- A `ConfigMap` referenced by `pod_environment_configmap`.
- A `Secret` referenced by `pod_environment_secret`.

Both of these resources allow `postgres-operator` to inject expected environment variables into the *Postgres* database pods. These environment variables are used by `wal-g` to access the specific S3 endpoint + bucket for storing/restoring backups (including cloning new clusters).

Each env-specific `kustomization.yaml` pulls in these two resources. For example, in `envs/pdx-dev3/kustomization.yaml` ([here](https://gitlab-master.nvidia.com/nvmetal/forged/-/blob/main/envs/pdx-dev3/kustomization.yaml)), you will see the following resource includes:

```
  - ../../overlays/postgres-operator-pod-env-configmap
  - ../../overlays/postgres-operator-pod-env-secret
```

You can read more about configuration options in the [postgres-operator administrator docs](https://github.com/zalando/postgres-operator/blob/master/docs/administrator.md).

### The pod_environment_configmap Resource

The purpose of this resource is to be a `ConfigMap` whose `data` fields map 1:1 to environment variables which get injected into the `forge-pg-cluster` pods (e.g. `forge-pg-cluster-0`, ...).

The overlay exists [here](https://gitlab-master.nvidia.com/nvmetal/forged/-/tree/main/overlays/postgres-operator-pod-env-configmap), and contains two resources:
- `forge-pg-cluster-backup-config.yaml`: This is an intermediary resource, and exists for the purpose of having organized data specific to backups. These values are read by `kustomize` and used by `replacements` to populate specific variables in `pod-env-configmap`.
- `pod-env-configmap.yaml`: This is the actual resource that is watched by the `postgres-operator` resource. It can contain **ANY** environment variables you want to inject into the pods, and is how you set backup/restore environment variables.

*Note: We could totally get rid of the intermediary `forge-pg-cluster-backup-config.yaml` file and just flatten it all into `pod-env-configmap.yaml`. The main reason I did this is there are a number of variables that are duplicated (e.g. AWS_SECRET_ACCESS_KEY and CLONE_AWS_SECRET_ACCESS_KEY), so it seemed nice to have a backup config that allows you to specify these things once, and then use replacements to put them in their proper places.*

### The pod_environment_secret Resource

This is the `Secret` resource which contains the access credentials for commnuicating with PBSS, and includes:
- `AWS_ACCESS_KEY_ID`: This is the login to the namespace (e.g. `team-forge`).
- `AWS_SECRET_ACCESS_KEY`: This is the password to the namespace for the given login.
- `WALG_LIBSODIUM_KEY`: This is the key used for encrypting/decrypting backups with `libsodium` using a [secretstream](https://libsodium.gitbook.io/doc/secret-key_cryptography/secretstream), which only requires a single key to encrypt/decrypt.

There are also corresponding `CLONE_*` variables, which are used for the restore flow (and cloning new clusters from existing backups). These should match their non-`CLONE` counterparts:
- `CLONE_AWS_ACCESS_KEY_ID`
- `CLONE_AWS_SECRET_ACCESS_KEY`
- `CLONE_WALG_LIBSODIUM_KEY`

More information about credentials is in the **Credentials** section above. More information about backup encryption is in the **Encryption** section below.

## Encryption

All backups are encrypted with [libsodium](https://github.com/jedisct1/libsodium) using the [secretstream](https://libsodium.gitbook.io/doc/secret-key_cryptography/secretstream) API, which allows for a single key to be used for encryption & decryption.

The key we use was generated via (which is also mentioned in [pod-env-secret.enc.yaml](https://gitlab-master.nvidia.com/nvmetal/forged/-/blob/main/overlays/postgres-operator-pod-env-secret/secrets/pod-env-secret.enc.yaml)):

```
openssl rand -hex 32
```

And subsequently, we set `WALG_LIBSODIUM_KEY_TRANSFORM: hex` in configuration (`wal-g` supports either `hex` or `base64` enocoded key as input).

`secretstream` does have support for key rotation. As of this writing I haven't checked, but if it's similar to `secretbox`, you're able to provide it a prioritized list of keys, and it will try every key in the list (allowing you to set a new key, followed by the older key, until everything has been rotated).

## Enabling Backups in a Site

Here are some reference MRs:
- [Example MR for enabling in qa2](https://gitlab-master.nvidia.com/nvmetal/forged/-/merge_requests/2539), which has some extra comments in the MR description for what's going on.
- [And there's this one for dev4](https://gitlab-master.nvidia.com/nvmetal/forged/-/merge_requests/2530), which is the same thing.

### Ensure The Bucket Exists

**As of now, we just have a `forge-pg-cluster` bucket that we dump all site backups to, so you shouldn't need to do this, unless you're switching to a new cluster that doesn't have the bucket yet.**

To verify the bucket exists, just get the `walS3Bucket` value you want to use (which is probably just `forge-pg-cluster`), and then check it:

```
s5cmd ls s3://<walS3Bucket>
```

If for some reason it doesn't exist, to create the bucket in a cluster, it's as simple as using the `mb` ("make bucket") command:

```
s5cmd mb s3://<walS3Bucket>
```

At some point, we might want to separate by a bucket per site, which would mean:
1. We'd need to create `s5cmd mb s3://forge-pg-cluster-<site>` for every new site we want to enable backups for
2. Change the `walS3Bucket` for a given site to match.

I could see this becoming a thing. It's not difficult, but it would mean that enabling backups in a site would require an extra step to create a bucket for that site.

### Enable Backups

This is as simple as dropping some patches in an environment-specific `kustomization.yaml` (see the reference MRs above) which is basically the same thing we do for enabling anything else. The core difference between sites is making sure the `sitePrefix` is set for the specific site, e.g.

```

  - patch: |-
      - op: replace
        path: /data/sitePrefix
        value: "reno-dev4-"
```

Once you merge the MR, go into *ArgoCD* and **sync!** At this point `postgres-operator` will notice the change to the configmaps, and will begin a rolling update to sync out the changes.

### Verifying Backups Are Working

Assuming you have done a `kubectl get pods -n postgres`, and you can see that all of the `forge-pg-cluster-[012]` pods have been updated within the past few minutes, you **should** be good to go!

At this point, it's just using `s5cmd` (see above for setup instructions) to make sure a `pg_basebackup` has been run, and that incremental WAL files are now being archived (if it's been > 5 minutes, you should see *at least* 1 WAL file):

```
s5cmd ls s3://forge-pg-cluster/spilo/<sitePrefix>-forge-pg-cluster*
```

You can also just list everything and grep, if you're not sure, e.g.

```
s5cmd ls s3://forge-pg-cluster* | grep dev4
```

You **should** see something like this:

```
❯ s5cmd ls -H s3://forge-pg-cluster/spilo*
2024/09/26 20:04:21            231.3K  spilo/forge-pg-cluster/wal/15/basebackups_005/base_0000000C0000000500000017/files_metadata.json
2024/09/26 20:04:20               387  spilo/forge-pg-cluster/wal/15/basebackups_005/base_0000000C0000000500000017/metadata.json
2024/09/26 20:04:17              4.8M  spilo/forge-pg-cluster/wal/15/basebackups_005/base_0000000C0000000500000017/tar_partitions/part_001.tar.br
2024/09/26 20:04:20               315  spilo/forge-pg-cluster/wal/15/basebackups_005/base_0000000C0000000500000017/tar_partitions/part_003.tar.br
2024/09/26 20:04:19               317  spilo/forge-pg-cluster/wal/15/basebackups_005/base_0000000C0000000500000017/tar_partitions/pg_control.tar.br
2024/09/26 20:04:21               395  spilo/forge-pg-cluster/wal/15/basebackups_005/base_0000000C0000000500000017_backup_stop_sentinel.json
2024/09/26 19:35:58               208  spilo/forge-pg-cluster/wal/15/wal_005/0000000B0000000500000013.br
2024/09/26 19:36:06               271  spilo/forge-pg-cluster/wal/15/wal_005/0000000B0000000500000014.partial.br
2024/09/26 19:36:05               152  spilo/forge-pg-cluster/wal/15/wal_005/0000000C.history.br
```

### Verify the cluster can detect the backups

Just because the backups are in PBSS doesn't mean the cluster can see them, so lets make sure it can!

First, drop into **any** of the `forge-pg-cluster` pods (it doesn't need to be the leader):

```
kubectl exec -it forge-pg-cluster-0 -n postgres -- bash
```

And now, simply list backups! You need to run the command with `envdir /run/etc/wal-e.d/env`, which sources in all of the environment variables used by `wal-g` (and `wal-e`):

```
root@forge-pg-cluster-0:/home/postgres# envdir /run/etc/wal-e.d/env wal-g backup-list
name                          modified             wal_segment_backup_start
base_000000040000002800000095 2024-10-19T00:13:10Z 000000040000002800000095
base_000000050000002900000024 2024-10-19T12:00:09Z 000000050000002900000024
base_0000000500000029000000B5 2024-10-20T00:00:10Z 0000000500000029000000B5
base_000000050000002A00000046 2024-10-20T12:00:05Z 000000050000002A00000046
base_000000050000002A000000D7 2024-10-21T00:00:06Z 000000050000002A000000D7
base_000000050000002B00000068 2024-10-21T12:00:08Z 000000050000002B00000068
base_000000050000002B000000F9 2024-10-22T00:00:08Z 000000050000002B000000F9
base_000000050000002C0000008A 2024-10-22T12:00:06Z 000000050000002C0000008A
base_000000050000002D0000001B 2024-10-23T00:00:08Z 000000050000002D0000001B
base_000000050000002D000000AC 2024-10-23T12:00:22Z 000000050000002D000000AC
base_000000050000002E000000CD 2024-10-24T12:00:06Z 000000050000002E000000CD
```

If you see at least one backup, you can now be comforted to know that backups are working and readable by the cluster!

*Note: When backups are enabled, the `backup-list` operation happens as part of a pod starting up (even if it doesn't need to restore from backup). If for some reason the endpoint (i.e. PBSS) is unavailable, or credentials are invalid (e.g. they changed), the `backup-list` operation will fail, and will keep trying indefinitely, effectively stopping the pod from starting up and joining the cluster. See `Cannot Connect to PBSS` for more.*

## Disabling Backups in a Site

To disable backups in a site, it's simply a matter of going to the `envs/<site>/kustomizaton.yaml`, and removing the `patch` for setting the `/data/walS3Bucket` value (OR explicitly setting it to an empty string): **an empty walS3Bucket value is how you disable backups entirely** -- this is the enable/disable switch for `wal-g`.

Once you disable, just run a sync in *ArgoCD*, at which point `postgres-operator` will notice the `pod-environment-configmap` change, and begin a rolling update of pods to disable backups.

At this point, you can choose to leave the backup data in PBSS, **or**, you can clean up after yourself:

Make sure you know what you're about to delete:
```
s5cmd ls s3://forge-pg-cluster/spilo/<sitePrefix>-forge-pg-cluster*
```

And then delete it:
```
s5cmd rm s3://forge-pg-cluster/spilo/<sitePrefix>-forge-pg-cluster*
```

## Runbook Types of Things/Troubleshooting

### PBSS is failing during pod startup due to connectivity or access.

When backups are enabled, the `backup-list` operation happens as part of a pod starting up (even if it doesn't need to restore from backup). If for some reason the endpoint (i.e. PBSS) is unavailable, or credentials are invalid (e.g. they changed), the `backup-list` operation will fail, and will keep trying indefinitely, effectively stopping the pod from starting up and joining the cluster.

This ends up manifesting as `postgres-operator` seeing something is wrong with the pod, and will then refuse to make any subsequent config changes to the cluster until the node is healthy.

This means, even if you push out an MR to fix credentials, or fix the endpoint, or even disable backups, `postgres-operator` will refuse to make changes, because the cluster is in an unhealthy/unsynced state. Unfortunately, this also means you now need to manually modify each pod manually to get you to your desired state, by:
1. Going into the `/run/etc/wal-e.d/env` directory.
2. Fixing each environment variable to your desired value.
3. Calling `patronictl reinit forge-pg-cluster`, and selecting the node you're on + fixing.

By calling `reinit`, it will kick off the initialization commands again, and load in the modified environment variables. Do **NOT** restart the pod -- if you do, it will revert back to the old environment variables, and then you'll just have to set them again.

### PBSS is failing, but all pods are already RUNNING.

If all pods are already running, you can either leave config as-is (if you know things will come back healthy later), OR, you can simply push out an MR with your desired changes. Since all pods are `RUNNING`, `postgres-operator` will see them as being in sync, and will be happy to apply your new changes.

**HOWEVER**, if your new changes **DON'T** correct the problem, and the rolling update causes the first pod to get stuck trying to communicate with PBSS, then you'll be in the `PBSS is failing during pod startup due to connectivity or access` situation. Try to avoid that. I'd say if you're unsure, it's safer to simply set `walS3Bucket` to an empty string to \[temporarily\] disable backups entirely.

### Verify backups are readable by the cluster.

First, drop into **any** of the `forge-pg-cluster` pods (it doesn't need to be the leader):

```
kubectl exec -it forge-pg-cluster-0 -n postgres -- bash
```

And now, simply list backups! You need to run the command with `envdir /run/etc/wal-e.d/env`, which sources in all of the environment variables used by `wal-g` (and `wal-e`):

```
root@forge-pg-cluster-0:/home/postgres# envdir /run/etc/wal-e.d/env wal-g backup-list
name                          modified             wal_segment_backup_start
base_000000040000002800000095 2024-10-19T00:13:10Z 000000040000002800000095
base_000000050000002900000024 2024-10-19T12:00:09Z 000000050000002900000024
base_0000000500000029000000B5 2024-10-20T00:00:10Z 0000000500000029000000B5
base_000000050000002A00000046 2024-10-20T12:00:05Z 000000050000002A00000046
base_000000050000002A000000D7 2024-10-21T00:00:06Z 000000050000002A000000D7
base_000000050000002B00000068 2024-10-21T12:00:08Z 000000050000002B00000068
base_000000050000002B000000F9 2024-10-22T00:00:08Z 000000050000002B000000F9
base_000000050000002C0000008A 2024-10-22T12:00:06Z 000000050000002C0000008A
base_000000050000002D0000001B 2024-10-23T00:00:08Z 000000050000002D0000001B
base_000000050000002D000000AC 2024-10-23T12:00:22Z 000000050000002D000000AC
base_000000050000002E000000CD 2024-10-24T12:00:06Z 000000050000002E000000CD
```

If you see at least one backup, you can now be comforted to know that backups are working and readable by the cluster!

### Wiping backups and/or initializing a fresh backup.

If for some reason backups get deleted (whether on accident or purpose) out from under a running cluster, it will keep writing WAL segments, but there will be no `pg_basebackup` to base against. You'll see something like this:

```
❯ s5cmd ls -H s3://forge-pg-cluster/spilo*
2024/09/26 19:35:58               208  spilo/forge-pg-cluster/wal/15/wal_005/0000000B0000000500000013.br
2024/09/26 19:36:06               271  spilo/forge-pg-cluster/wal/15/wal_005/0000000B0000000500000014.partial.br
2024/09/26 19:36:05               152  spilo/forge-pg-cluster/wal/15/wal_005/0000000C.history.br
2024/09/26 19:41:05            861.0K  spilo/forge-pg-cluster/wal/15/wal_005/0000000C0000000500000014.br
2024/09/26 19:46:04               231  spilo/forge-pg-cluster/wal/15/wal_005/0000000C0000000500000015.br
```

So, you need to fix this. One option would be to restart the pod(s), and the leader will do its own `pg_basebackup`. Another option, which I think is less disruptive (no restarts), is to just manually kick off a `pg_basebackup`.

First, figure out the primary node:
```
❯ kubectl exec -it forge-pg-cluster-0 -n postgres -- bash
Defaulted container "postgres" out of: postgres, postgres-exporter

 ____        _ _
/ ___| _ __ (_) | ___
\___ \| '_ \| | |/ _ \
 ___) | |_) | | | (_) |
|____/| .__/|_|_|\___/
      |_|

This container is managed by runit, when stopping/starting services use sv

Examples:

sv stop cron
sv restart patroni

Current status: (sv status /etc/service/*)

run: /etc/service/cron: (pid 36) 502521s
run: /etc/service/patroni: (pid 35) 502521s
run: /etc/service/pgqd: (pid 34) 502521s
root@forge-pg-cluster-0:/home/postgres# patronictl topology
+ Cluster: forge-pg-cluster -------------+--------------+---------+----+-----------+
| Member               | Host            | Role         | State   | TL | Lag in MB |
+----------------------+-----------------+--------------+---------+----+-----------+
| forge-pg-cluster-0   | 100.113.63.209  | Leader       | running |  5 |           |
| + forge-pg-cluster-1 | 100.113.179.240 | Replica      | running |  5 |         0 |
| + forge-pg-cluster-2 | 100.123.163.127 | Sync Standby | running |  5 |         0 |
+----------------------+-----------------+--------------+---------+----+-----------+
root@forge-pg-cluster-0:/home/postgres#
```

And now jump onto the primary node and drop into the `postgres` user:

```
❯ kubectl exec -it forge-pg-cluster-0 -n postgres -- bash
$ su postgres
$ crontab -e
```

And hey look, you'll see the line!

```
0 */12 * * * envdir "/run/etc/wal-e.d/env" /scripts/postgres_backup.sh "/home/postgres/pgdata/pgroot/data"
```

Now run it (still as the `postgres` user):
```
envdir "/run/etc/wal-e.d/env" /scripts/postgres_backup.sh "/home/postgres/pgdata/pgroot/data"
```

And you'll see it ran:
```
postgres@forge-pg-cluster-0:~$ envdir "/run/etc/wal-e.d/env" /scripts/postgres_backup.sh "/home/postgres/pgdata/pgroot/data"
2024-09-26 20:04:16.539 - /scripts/postgres_backup.sh - I was called as: /scripts/postgres_backup.sh /home/postgres/pgdata/pgroot/data
2024-09-26 20:04:17.195 - /scripts/postgres_backup.sh - producing a new backup
INFO: 2024/09/26 20:04:17.274194 Calling pg_start_backup()
INFO: 2024/09/26 20:04:17.394509 Starting a new tar bundle
INFO: 2024/09/26 20:04:17.394551 Walking ...
INFO: 2024/09/26 20:04:17.394808 Starting part 1 ...
INFO: 2024/09/26 20:04:17.653245 Packing ...
INFO: 2024/09/26 20:04:17.655369 Finished writing part 1.
INFO: 2024/09/26 20:04:20.004362 Starting part 2 ...
INFO: 2024/09/26 20:04:20.004480 /global/pg_control
INFO: 2024/09/26 20:04:20.005941 Finished writing part 2.
INFO: 2024/09/26 20:04:20.005979 Calling pg_stop_backup()
INFO: 2024/09/26 20:04:20.035998 Starting part 3 ...
INFO: 2024/09/26 20:04:20.036191 backup_label
INFO: 2024/09/26 20:04:20.036215 tablespace_map
INFO: 2024/09/26 20:04:20.045019 Finished writing part 3.
INFO: 2024/09/26 20:04:21.908119 Wrote backup with name base_0000000C0000000500000017
```

And now check PBSS again, and you'll see the base backup (which is the new base for subsequent WAL segments):
```
❯ s5cmd ls -H s3://forge-pg-cluster/spilo*
2024/09/26 20:04:21            231.3K  spilo/forge-pg-cluster/wal/15/basebackups_005/base_0000000C0000000500000017/files_metadata.json
2024/09/26 20:04:20               387  spilo/forge-pg-cluster/wal/15/basebackups_005/base_0000000C0000000500000017/metadata.json
2024/09/26 20:04:17              4.8M  spilo/forge-pg-cluster/wal/15/basebackups_005/base_0000000C0000000500000017/tar_partitions/part_001.tar.br
2024/09/26 20:04:20               315  spilo/forge-pg-cluster/wal/15/basebackups_005/base_0000000C0000000500000017/tar_partitions/part_003.tar.br
2024/09/26 20:04:19               317  spilo/forge-pg-cluster/wal/15/basebackups_005/base_0000000C0000000500000017/tar_partitions/pg_control.tar.br
2024/09/26 20:04:21               395  spilo/forge-pg-cluster/wal/15/basebackups_005/base_0000000C0000000500000017_backup_stop_sentinel.json
2024/09/26 19:35:58               208  spilo/forge-pg-cluster/wal/15/wal_005/0000000B0000000500000013.br
2024/09/26 19:36:06               271  spilo/forge-pg-cluster/wal/15/wal_005/0000000B0000000500000014.partial.br
2024/09/26 19:36:05               152  spilo/forge-pg-cluster/wal/15/wal_005/0000000C.history.br
2024/09/26 19:41:05            861.0K  spilo/forge-pg-cluster/wal/15/wal_005/0000000C0000000500000014.br
2024/09/26 19:46:04               231  spilo/forge-pg-cluster/wal/15/wal_005/0000000C0000000500000015.br
2024/09/26 20:04:17              1.1K  spilo/forge-pg-cluster/wal/15/wal_005/0000000C0000000500000016.br
2024/09/26 20:04:20               236  spilo/forge-pg-cluster/wal/15/wal_005/0000000C0000000500000017.00000028.backup.br
2024/09/26 20:04:20               227  spilo/forge-pg-cluster/wal/15/wal_005/0000000C0000000500000017.br
```

### Restoring a cluster from an existing backup.

To restore a cluster from an existing backup, it's as simple as setting the `clone` section, giving it the same cluster name as itself, and the point-in-time recovery (PITR) timestamp you want to restore from. This will take the timestamp you give it, and then find the closest timestamp (going backwards in time). If you give it 12:05:08, it might not find 12:05:08, but it will go back until it finds something (e.g. 12:05:03), and then restore from that.

You can do this either by making an MR, or just modifying the `postgresql` resource directly (which might be best, since this is thought of as a temporary thing to bootstrap a cluster and then remove it):

```
$ kubectl edit postgresql -n postgres
```

And then, in the `spec` section, add a `clone` section:

```
spec:
  ........
  clone:
    cluster: "forge-pg-cluster"
    timestamp: "2024-10-02T06:27:30+00:00"  # Or whatever time you want.
  ........
```

After you apply the change, you can do a couple of things next:
- If the cluster is already broken, `postgres-operator` will eventually sync things up, and the leader will restore from the backup.
- If the cluster is already broken, and you want to fast track it: `kubectl delete postgresql -n postgres forge-pg-cluster`. But keep in mind this is extra destructive, so this is really if things are super hosed anyway.

### Creating a cluster clone from an existing backup (to verify/audit they work, playground, etc).

This is all work based out of the `nvmetal/forged` repo. The idea is you create a new database cluster (with a name other than `forge-pg-cluster`, for example, `forge-pg-cluster-clone`) and then restore it from a backup from an existing `forge-pg-cluster`.

In this case, you will:
1. Go into `components/forge-pg-cluster`
2. Copy `forge-pg-cluster.yaml` to `forge-pg-cluster-clone.yaml`.
3. Add `forge-pg-cluster-clone.yaml` to the `kustomization.yaml` resources.
4. Modify `forge-pg-cluster-clone.yaml` so the `metadata.name` is `forge-pg-cluster-clone`.
5. Add a `clone` section (just like above), referencing the primary `forge-pg-cluster` and the timestamp you want to clone from.

Once you apply the change (either by making an MR + merging + ArgoCD sync, or simply doing something like `just build . | kubectl apply -n postgres -f -`), it will start up the new `forge-pg-cluster-clone` cluster, and restore from the backups of its local `forge-pg-cluster`.

From there, you will have a completely separate cluster that nothing is talking to. You can use it verify the backup process works, that backups work in general, and have a fully populated database to play around with -- have fun! **BUT! REMEMBER! If you keep the config an exact clone, it means the forge-pg-cluster-clone will ALSO be writing backups, so you'll end up with, say, pdx-dev3-forge-pg-cluster-clone backup data as well**. It's not the end of the world -- just don't forget to clean it up. :)
