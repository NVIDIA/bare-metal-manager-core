# `nico-admin-cli machine show`

_[Hardware commands](../../hardware.md) › [machine](./machine.md) › **show**_

## NAME

nico-admin-cli-machine-show - Display Machine information

## SYNOPSIS

**nico-admin-cli machine show** \[**--help**\] \[**-a**\|**--all**\]
\[**-d**\|**--dpus**\] \[**-h**\|**--hosts**\]
\[**-t**\|**--instance-type-id**\] \[**-c**\|**--history-count**\]
\[**--max-width**\] \[**--columns**\] \[**--extended**\]
\[**--sort-by**\] \[*MACHINE*\]

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

**--max-width** *\<\[COLUMN=\]WIDTH\>*  
Limit displayed column width to WIDTH characters, truncating longer
values with .... Repeatable. A bare WIDTH applies to every column;
COLUMN=WIDTH limits just that column, where COLUMN must exactly match
the columns displayed header text (case-insensitive), e.g. State=40. For
a header containing spaces, quote the whole COLUMN=WIDTH argument, e.g.
"State Version=40". An unmatched COLUMN is ignored with a warning
listing the valid headers for this invocation.

**--columns** *\<COLUMN\>*  
Only show these columns, in the order given. Comma-separated and/or
repeatable. COLUMN must exactly match the columns displayed header text
(case-insensitive), e.g. --columns id,state. For a header containing
spaces, quote it, e.g. --columns "id,state version". Omit to show every
column in the table's normal order. An unmatched COLUMN is ignored with a
warning listing the valid headers for this invocation.

**--extended**  
Extended result output.

This used by measured boot, where basic output contains just what you
probably care about, and "extended" output also dumps out all the
internal UUIDs that are used to associate instances.

**--sort-by** *\<SORT_BY\>* \[default: primary-id\]  
Sort output by specified field\

\
*Possible values:*

- primary-id: Sort by the primary ID

- state: Sort by state

\[*MACHINE*\]  
The machine ID to query. Omit to show all machines.

## Examples

```sh
nico-admin-cli machine show
nico-admin-cli machine show 12345678-1234-5678-90ab-cdef01234567
nico-admin-cli machine show --dpus
nico-admin-cli machine show --hosts
nico-admin-cli machine show --max-width 20
nico-admin-cli machine show --max-width "State Version=20"
nico-admin-cli machine show --columns state,id,"attached dpus"
```

---

**See also:** [Hardware commands](../../hardware.md) · [CLI reference index](../../README.md)
