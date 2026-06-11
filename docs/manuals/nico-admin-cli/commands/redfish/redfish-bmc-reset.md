# `nico-admin-cli redfish bmc-reset`

_[Hardware commands](../../hardware.md) › [redfish](./redfish.md) › **bmc-reset**_

## NAME

nico-admin-cli-redfish-bmc-reset - Reboot the BMC itself

## SYNOPSIS

**nico-admin-cli redfish bmc-reset** \[**--extended**\]
\[**--sort-by**\] \[**-h**\|**--help**\]

## DESCRIPTION

Reboot the BMC itself

## OPTIONS

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

---

**See also:** [Hardware commands](../../hardware.md) · [CLI reference index](../../README.md)
