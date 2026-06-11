# `nico-admin-cli switch force-delete`

_[Hardware commands](../../hardware.md) › [switch](./switch.md) › **force-delete**_

## NAME

nico-admin-cli-switch-force-delete - Force delete a switch and
optionally its interfaces

## SYNOPSIS

**nico-admin-cli switch force-delete**
\[**-d**\|**--delete-interfaces**\] \[**--extended**\] \[**--sort-by**\]
\[**-h**\|**--help**\] \<*SWITCH_ID*\>

## DESCRIPTION

Force delete a switch and optionally its interfaces

## OPTIONS

**-d**, **--delete-interfaces**  
Delete machine interfaces associated with this switch.

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

\<*SWITCH_ID*\>  
Switch ID to force delete.

## Examples

```sh
nico-admin-cli switch force-delete 12345678-1234-5678-90ab-cdef01234567
nico-admin-cli switch force-delete 12345678-1234-5678-90ab-cdef01234567 --delete-interfaces
```

---

**See also:** [Hardware commands](../../hardware.md) · [CLI reference index](../../README.md)
