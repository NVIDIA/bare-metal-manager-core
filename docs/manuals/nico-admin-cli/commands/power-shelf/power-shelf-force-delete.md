# `nico-admin-cli power-shelf force-delete`

_[Hardware commands](../../hardware.md) › [power-shelf](./power-shelf.md) › **force-delete**_

## NAME

nico-admin-cli-power-shelf-force-delete - Force delete a power shelf and
optionally its interfaces

## SYNOPSIS

**nico-admin-cli power-shelf force-delete**
\[**-d**\|**--delete-interfaces**\] \[**--extended**\] \[**--sort-by**\]
\[**-h**\|**--help**\] \<*POWER_SHELF_ID*\>

## DESCRIPTION

Force delete a power shelf and optionally its interfaces

## OPTIONS

**-d**, **--delete-interfaces**  
Delete machine interfaces associated with this power shelf.

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

\<*POWER_SHELF_ID*\>  
Power Shelf ID to force delete.

## Examples

```sh
nico-admin-cli power-shelf force-delete 12345678-1234-5678-90ab-cdef01234567
nico-admin-cli power-shelf force-delete 12345678-1234-5678-90ab-cdef01234567 --delete-interfaces
```

---

**See also:** [Hardware commands](../../hardware.md) · [CLI reference index](../../README.md)
