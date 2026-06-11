# `nico-admin-cli managed-host show`

_[Hardware commands](../../hardware.md) › [managed-host](./managed-host.md) › **show**_

## NAME

nico-admin-cli-managed-host-show - Display managed host information

## SYNOPSIS

**nico-admin-cli managed-host show** \[**--help**\]
\[**-a**\|**--all**\] \[**-i**\|**--ips**\]
\[**-t**\|**--instance-type-id**\] \[**-m**\|**--more**\] \[**--fix**\]
\[**--quarantine**\] \[**--extended**\] \[**--sort-by**\] \[*MACHINE*\]

## DESCRIPTION

Display managed host information

## OPTIONS

**--help**  
**-a**, **--all**  
Show all managed hosts (DEPRECATED)

**-i**, **--ips**  
Show IP details in summary

**-t**, **--instance-type-id** *\<INSTANCE_TYPE_ID\>*  
Show only hosts for this instance type

**-m**, **--more**  
Show GPU and memory details in summary

**--fix**  
Show only hosts in maintenance mode

**--quarantine**  
Show only hosts in quarantine

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
Show managed host specific details (using host or dpu machine id), leave
empty for all

## Examples

```sh
nico-admin-cli managed-host show
nico-admin-cli managed-host show 12345678-1234-5678-90ab-cdef01234567
nico-admin-cli managed-host show --ips
```

---

**See also:** [Hardware commands](../../hardware.md) · [CLI reference index](../../README.md)
