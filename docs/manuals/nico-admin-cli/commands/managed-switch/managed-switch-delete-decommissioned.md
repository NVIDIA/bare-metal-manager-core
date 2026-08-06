# `nico-admin-cli managed-switch delete-decommissioned`

_[Hardware commands](../../hardware.md) › [managed-switch](./managed-switch.md) › **delete-decommissioned**_

## NAME

nico-admin-cli-managed-switch-delete-decommissioned - Permanently delete
a decommissioned managed switch

## SYNOPSIS

**nico-admin-cli managed-switch delete-decommissioned**
\[**--extended**\] \[**--sort-by**\] \[**-h**\|**--help**\]
\<*SWITCH_ID*\>

## DESCRIPTION

Permanently delete a decommissioned managed switch

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

\<*SWITCH_ID*\>  
ID of the decommissioned managed switch to permanently delete

## Examples

```sh
nico-admin-cli managed-switch delete-decommissioned sw100nsner0op5osl6n85t7772j010jmhafm934n7oej4mlome3okrn9b60
```

---

**See also:** [Hardware commands](../../hardware.md) · [CLI reference index](../../README.md)
