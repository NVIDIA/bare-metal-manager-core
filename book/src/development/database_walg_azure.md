# Playing with wal-g + Azure Postgres Backups

This guide shows how to back up a local Postgre database to Azure Storage with [wal-g](https://github.com/wal-g/wal-g),
and how to restore and verify a backup. It's intent is to do the steps manually to show you how it all works behind the
scenes. In actual sites, we let `postgres-operator` + `Spilo` handle all of it for us, but at the lowest level, this is
what it's managing for us.

***

## Prerequisites

- `homebrew`, assuming you're on macOS. Any OS is fine, but I'm doing this from a Mac, mainly re: the steps for
  installing `az` and `azcopy`. You can of course do it however you want. Everything beyond installing `az` and `azcopy`
  is OS agnostic.
- A working Postgres database running on your machine, which is also pretty easy. You can `homebrew` that as well and
  get something started up.
- An Azure storage account with credentials.

In this example, our Azure storage account name is `forgedbuswest3`.

***

## Software Installation

### wal-g

First, lets get `wal-g` installed via `homebrew`.

```
brew install wal-g
```

Make sure you have the `wal-g-pg` command (for Postgres backups):

```
which `wal-g-pg`
```

***

### az & azcopy

Next, lets get our Azure tools installed (`az` and `azcopy`). Install both via Homebrew:

```
brew install azure-cli
brew install azcopy
```

- `az` lets you manage Azure resources (create containers, list accounts, etc).
- `azcopy` is good for creating/moving/listing files in containers.

***

## Environment Setup

### Azure-specific environment vars

First, add some environment variables to get `az` and `azcopy` working:

```
# used by az
export AZURE_CLIENT_ID="your-app-id"
export AZURE_TENANT_ID="your-tenant-id"
export AZURE_CLIENT_SECRET="your-client-secret"
# used by azcopy
export AZCOPY_SPA_APPLICATION_ID="${AZURE_CLIENT_ID}"
export AZCOPY_SPA_CLIENT_SECRET="${AZURE_CLIENT_SECRET}"
```

### wal-g environment variables

Next, we need environment variables for `wal-g`, including:

- Where to store backups (`WALG_AZ_PREFIX`).
- How to talk to Postgres (`PG*` vars).

```
# This is used in the context of the full
# URL, e.g. https://${AZURE_STORAGE_ACCOUNT}.blob.core.windows.net
export AZURE_STORAGE_ACCOUNT="forgedbuswest3"

# This isn't actually used by wal-g at all, but I
# create it mainly for convenience and readability
# throughout the rest of this.
AZURE_STORAGE_CONTAINER="chet-testing"

# This takes the format <container>/<dir> -- the container will
# need to be created in advance using az.
export WALG_AZ_PREFIX="azure://${AZURE_STORAGE_CONTAINER}/wal-g-pg-backups"

# And then all of the Postgres connection variables; wal-g
# just uses the same ones that Postgres does.
export PGHOST=localhost
export PGUSER=postgres
export PGPORT=5432

# If needed. For testing I don't have a password
# on my local Postgres instance.
# export PGPASSWORD=xxx
```

***

### Ensure the Azure container exists for backups

List containers to see if it exists yet:

```
az storage container list --account-name ${AZURE_STORAGE_ACCOUNT} -o table
```

If not, I create one called `chet-testing` (which I assigned into `${AZURE_STORAGE_CONTAINER}` above):

```
# You can use az:
az storage container create --name ${AZURE_STORAGE_CONTAINER} --account-name ${AZURE_STORAGE_ACCOUNT}

# Or azcopy:
azcopy make https://${AZURE_STORAGE_ACCOUNT}.blob.core.windows.net/${AZURE_STORAGE_CONTAINER}
```

***

## Creating a Backup

To create a backup, we'll be using the `wal-g-pg backup-push` command.

Behind the scenes, when you run this, a few things happen:

1. `wal-g` connects to Postgres and issues a `SELECT pg_start_backup('wal-g', true, false)` tell it it's starting a
   backup
2. `wal-g` starts copying almost everything (sans pid files and such) from pgdata out to Azure.
3. `wal-g` issues a `SELECT pg_stop_backup();` once the copy to Azure is done.

This is basically what happens when you do a `pg_basebackup`.

Upon issuing the `pg_stop_backup()`, Postgres will then:

- Write out a `tablespace_map` file for itself (if needed).
- Write out a `backup_label` file for itself.
- Return a `start_lsn` and `finish_lsn` for `wal-g`.

`wal-g` will then copy those over to Azure as well, and then generate a `sentinel` file and `metadata.json` file that
also gets copied into Azure (these are only consumed by `wal-g`, and `tablespace_map` and `backup_label` are consumed by
Postgres).

Example `backup_label` file that Postgres consumes if you need to restore:

```
START WAL LOCATION: 0/5000028 (file 000000010000000000000005)
CHECKPOINT LOCATION: 0/5000060
BACKUP METHOD: streamed
BACKUP FROM: master
START TIME: 2025-10-02 11:34:43 PDT
LABEL: wal-g
```

Okay all said, lets do it!

### 1. Find your Postgres data directory to backup.

We need to tell `wal-g` the actual pgdata directory to do a base backup of.

```
psql -U postgres -c "show data_directory"
         data_directory
---------------------------------
 /opt/homebrew/var/postgresql@15
(1 row)
```

***

### 2. Push a base backup

Now we push it! Note that this is not a COMPLETE backup. A COMPLETE backup is a base backup + the subsequent WAL segment
to complete the backup. When a backup starts, we assume changes will come in during the initial base backup, so a final
WAL segment is required to be also pushed (we'll get to that in the following steps).

Push it!

```
wal-g-pg backup-push /opt/homebrew/var/postgresql@15
```

And you'll see something like:

```
INFO: Backup will be pushed to storage: default
INFO: Calling pg_start_backup()
INFO: Starting a new tar bundle
INFO: Finished writing part 1.
INFO: Calling pg_stop_backup()
INFO: Wrote backup with name base_000000010000000000000005 to storage default
```

***

### 3. Confirm the data is in Azure

Now we can just use `azcopy` to see that the base backup worked!

```
# e.g. azcopy list https://forgedbuswest3.blob.core.windows.net/chet-testing
azcopy list https://${AZURE_STORAGE_ACCOUNT}.blob.core.windows.net/${AZURE_STORAGE_CONTAINER}
```

And we'll see:

```
wal-g-pg-backups/basebackups_005/base_000000010000000000000005_backup_stop_sentinel.json; Content Length: 425.00 B
wal-g-pg-backups/basebackups_005/base_000000010000000000000005/files_metadata.json; Content Length: 169.15 KiB
wal-g-pg-backups/basebackups_005/base_000000010000000000000005/metadata.json; Content Length: 375.00 B
wal-g-pg-backups/basebackups_005/base_000000010000000000000005/tar_partitions/backup_label.tar.lz4; Content Length: 373.00 B
wal-g-pg-backups/basebackups_005/base_000000010000000000000005/tar_partitions/part_001.tar.lz4; Content Length: 4.25 MiB
wal-g-pg-backups/basebackups_005/base_000000010000000000000005/tar_partitions/pg_control.tar.lz4; Content Length: 399.00 B
```

***

### 4. Push the "closing" WAL segment

Each base backup notes the WAL file needed for consistency. THe importance of this is that the "
`SELECT pg_stop_backup();`" record is contained in this WAL segment, and is how Postgres knows it has a consistent
backup. If it tries to read a base backup without finding this record, it won't know any checkpoint info, the LSN where
the backup ends, etc. This statement is what also creates the backup_label file.

From the name base name `000000010000000000000005`, this tells us the actual WAL segment in the `pg_wal` directory (
`/pg_wal/000000010000000000000005`).

So now we push the WAL segment (note that in real life, the `postgresql.conf` entry for `archive_command` will fire this
off automatically -- the idea is once you stop a backup, it will need a "closing" segment to complete the backup, so it
fires off the `archive_command`, even if it's technically early to fire it (and not as part of `wal_segment_size` being
hit, or an `archive_timeout` being hit).

```
wal-g-pg wal-push /opt/homebrew/var/postgresql@15/pg_wal/000000010000000000000005
```

To which you'll see it log:

```
INFO: 2025/10/02 12:10:10.417602 FILE PATH: 000000010000000000000005.lz4
```

And then you can use `azcopy` to see that it's now there:

```
❯ azcopy list https://forgedbuswest3.blob.core.windows.net/chet-testing | grep wal_
wal-g-pg-backups/wal_005/000000010000000000000005.lz4; Content Length: 64.57 KiB
```

At this point, we should have a complete backup that we can restore from. Very exciting!
***

## Restoring from a Backup

To restore from a backup, we just need to make a temporary directory, tell `wal-g` to dump the base backup to it, and
then initialize a new database with the files in there.

Since the backup is technically incomplete, Postgres will leverage whatever is configured for `restore_command` to fetch
any additional WAL segments to complete the restore, so we set the `restore_command` to use `wal-g-pg wal-fetch %f %p`,
where Postgres will pass `%f` as the WAL segment it needs, and `%p` as the place Postgres wants `wal-g` to write it to.

In the case of this, it would expand to something like:

```
wal-g-pg wal-fetch 000000010000000000000005 /tmp/pg-restore/pg_wal/000000010000000000000005
```

Okay so, lets go!

### 1. Prepare the tmp dir to test the restore

We can just make a `/tmp/pg-restore` dir to play with.

```
mkdir -p /tmp/pg-restore
```

### 2. Fetch the backup into the tmp dir.

We'll just restore the `LATEST` here, where the latest means that `wal-g` will look at all of the base backups in the
storage path, sort them by their finish LSN, and pull down the most recent base.

```
wal-g-pg backup-fetch /tmp/pg-restore LATEST
```

Again, this pulls down the base files only, and we will now rely on the `restore_command` and `wal-g-pg wal-fetch` (
below) to go and get the completing WAL segment, plus any additional WAL segments. Remember: we do a base backup at some
longer interval, and then fill it in by pulling down and replaying WAL segments to catch back up. It will keep asking
for more WAL segments until `wal-g` says there aren't any more.

HOWEVER, in the example below, we do something super duper special:

```
recovery_target = 'immediate'
```

This says "just get the single WAL file we need to complete the backup, and ignore trying to get more." For the purpose
of this example, it's fine, but for real production environments, it's not. What would end up happening is you'd lose
all subsequent updates until the next base backup, restore from an older point in time, and then your timeline would
diverge as soon as you started serving from it.

In real production cases, you'd want:

```
recovery_target = 'latest`
```

Which is also the default if you don't set anything (and you'll see Postgres logging trying to fetch more segments in
this case).

Okay, so now we've created a temp dir and pulled down the base backup. Let's carry on to getting configs ready so we can
start up Postgres and have it restore!
***

### 3. Configure recovery

Lets build a `postgresql.auto.conf`, which overrides values from `postgresql.conf`. When Postgres starts up, it will see
that the `recovery.signal` file exists, which tells it that it's in recovery mode, and to use `restore_command`,
`restore_target`, and `restore_target_action`.

Upon recovery, it will delete the `recovery.signal` file, so the settings in `postgresql.auto.conf` get ignored, but
it's a good idea to also clean that up too.

Let's just dump the settings into a file (we explained `restore_command` and `recovery_target` above), and write out the
`recovery.signal` file.

The one thing we didn't discuss here yet is `recovery_target_action`, for which there are a few options:

- `pause` (this is actually the default)
- `promote`
- `shutdown`

#### pause

In the case of `pause`, it will read up to as many WAL segments as you configured (
`recovery_target=<immediate|latest>`), and then pause in a read-only standby mode, giving you a chance to look through
the data and verify things before you re-introduce it. This is also a time you can manually call
`SELECT pg_wal_replay_resume()` to fetch additional WAL segments beyond `recovery_target=immediate`. Once you're happy,
you can call `SELECT pg_promote();` and make it read/write again.

#### promote

In the case of `promote`, it will self-promote once it is consistent based on the configs you gave it. For automated
systems, this is what is used, and no operator intervention is required.

#### shutdown

In the case of `shutdown`, it will literally shut down once it is consistent based on the configs you gave it. This is
one way to load a backup that you know is consistent, can use for verifying backups, and then have it stored on a local
disk (if desired).

Okay, all said, lets keep going!

```
cat > /tmp/pg-restore/postgresql.auto.conf <<'EOF'
restore_command = 'wal-g-pg wal-fetch %f %p'
recovery_target = 'immediate'
recovery_target_action = 'promote'
EOF

touch /tmp/pg-restore/recovery.signal
```

And now lets start up Postgres and watch it load up our base backup, and then load + replay WAL segments from Azure!

***

### 4. Start a Postgres instance on an "ephemeral" port

In this case, we just want to start up an instance of Postgres on some ephemeral port, pointing it at our temp dir:

```
pg_ctl -D /tmp/pg-restore -o "-p 55432" start
```

This will immediately daemonize, but you will see some logs dumped out in the process of it loading + daemonizing.

You should see something like:

```
LOG:  restored log file "000000010000000000000005" from archive
LOG:  consistent recovery state reached ...
LOG:  database system is ready to accept connections
```

Boom shaka laka, it worked! So lets check it out!
***

### 5. Inspect the restored DB

Since we have a running Postgres instance, we can use `psql` to drop in and check it out:

```
psql -U postgres -p 55432
postgres=# \d

List of relations
 Schema |   Name   | Type  |  Owner
--------+----------+-------+----------
 public | test_tbl | table | postgres

postgres=# SELECT * FROM test_tbl;
```

Pretty fun!
***

### 6. Stop and clean up

Okay, now that we know it works, lets clean up.

```
pg_ctl -D /tmp/pg-restore stop -m fast
rm -rf /tmp/pg-restore
```

***

## Doing Backup Testing

This is something we can decide on, but the flow above is literally how we would do backup testing. The idea is we would
have a pod that runs, pulls down data from Azure, and does a restore. We could do it a couple of ways.

If we did a `pause` (or `promote`, since it wouldn't matter), with `recovery_target = 'latest'`, we could effectively
make sure we're able to do a full restore of the database. We'd load it up, then fire off some known queries at both it
AND the actual `forge-pg-cluster` database to verify some type of consistency between the two.

OR, we could also do `recovery_target_action=shutdown`, and then just verify the metadata about the database to feel
comfortable knowing it was able to become consistent and hit a point in time we're happy with.

Another thing we could also leverage is specifying the exact point in time we want to restore to, which could be a nice
way to verify a specific backup worked and included a specific record. The options we have to use here are:

- `recovery_target_time` -- e.g. `2025-10-02 11:00:00-07`
- `recovery_target_lsn` -- e.g. `0/5000100`
- `recovery_target_inclusive` -- e.g. `true/false` (stop up to, or including, the LSN/time)

One possible workflow if we're doing testing, we insert a sentinel row of sorts, do a backup, then restore into a
temporary database and confirm the sentinel row is there. There's a lot we can do in there!

## Retention and Delete

It's also worth noting that, without cleanup, backups and WALs accumulate forever. `wal-g` supports delete policies,
and `postgres-operator` has support for implementing some of this, but behind the scenes, here are some things
you can run:

- Keep last 7 base backups (and required WAL):

```
wal-g-pg delete retain FULL 7 --confirm
```

- Delete backups older than some timestamp:

```
wal-g-pg delete before 2025-10-15T00:00:00Z --confirm
```

- And you can dry run all of it (to see what would be deleted):

```
wal-g-pg delete retain FULL 7 --dry-run
```

***

## Production Config

We didn't do this in this doc, since it was all about manual testing to see how it works, but behind the scenes,
`postgres-operator` will drop this into `postgresql.conf` to automatically ship WAL segments (the thing we ran
manually):

```
wal_level = replica
archive_mode = on
archive_command = 'wal-g-pg wal-push %p'
```