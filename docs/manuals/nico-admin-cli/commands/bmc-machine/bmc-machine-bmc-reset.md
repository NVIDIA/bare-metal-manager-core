# `nico-admin-cli bmc-machine bmc-reset`

_[Hardware commands](../../hardware.md) › [bmc-machine](./bmc-machine.md) › **bmc-reset**_

## NAME

nico-admin-cli-bmc-machine-bmc-reset - Reset BMC

## SYNOPSIS

**nico-admin-cli bmc-machine bmc-reset** \<**--machine**\>
\[**-u**\|**--use-ipmitool**\] \[**--extended**\] \[**--sort-by**\]
\[**-h**\|**--help**\]

## DESCRIPTION

Reset BMC

## OPTIONS

**--machine** *\<MACHINE\>*  
ID of the machine to reboot

**-u**, **--use-ipmitool**  
Use ipmitool instead of Redfish to reset the BMC. ipmitool bmc reset
requests may be silently ignored if the BMC is in lockdown mode.

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

**-h**, **--help**  
Print help (see a summary with -h)

## Examples

```sh
nico-admin-cli bmc-machine bmc-reset --machine 12345678-1234-5678-90ab-cdef01234567
nico-admin-cli bmc-machine bmc-reset --machine 12345678-1234-5678-90ab-cdef01234567 --use-ipmitool
```

---

**See also:** [Hardware commands](../../hardware.md) · [CLI reference index](../../README.md)
