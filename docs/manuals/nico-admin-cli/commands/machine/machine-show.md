# `nico-admin-cli machine show`

_[Hardware commands](../../hardware.md) › [machine](./machine.md) › **show**_

## NAME

nico-admin-cli-machine-show - Display Machine information

## SYNOPSIS

**nico-admin-cli machine show** \[**--help**\] \[**-a**\|**--all**\]
\[**-d**\|**--dpus**\] \[**-h**\|**--hosts**\]
\[**-t**\|**--instance-type-id**\] \[**-c**\|**--history-count**\]
\[**--extended**\] \[**--sort-by**\] \[*MACHINE*\]

## DESCRIPTION

Display Machine information

## OPTIONS

**--help**  
**-a**, **--all**  
Show all machines (DEPRECATED)

**-d**, **--dpus**  
Show only DPUs

**-h**, **--hosts**  
Show only hosts

**-t**, **--instance-type-id** *\<INSTANCE_TYPE_ID\>*  
Show only machines for this instance type

**-c**, **--history-count** *\<HISTORY_COUNT\>* \[default: 5\]  
History count. Valid if \`machine\` argument is passed.

**--extended**  
Extended result output.

This used by measured boot, where basic output contains just what you
probably care about, and "extended" output also dumps out all the
internal UUIDs that are used to associate instances.

**--sort-by** *\<SORT_BY\>* \[default: primary-id\]  
Sort output by specified field\

\
*Possible values:*

- primary-id: Sort by the primary id

- state: Sort by state

\[*MACHINE*\]  
The machine ID to query. Omit to show all machines.

## Examples

```sh
nico-admin-cli machine show
nico-admin-cli machine show 12345678-1234-5678-90ab-cdef01234567
nico-admin-cli machine show --dpus
nico-admin-cli machine show --hosts
```

---

**See also:** [Hardware commands](../../hardware.md) · [CLI reference index](../../README.md)
