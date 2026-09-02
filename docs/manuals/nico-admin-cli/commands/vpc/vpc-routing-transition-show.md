# `nico-admin-cli vpc routing-transition show`

_[Network commands](../../network.md) › [vpc](./vpc.md) › [routing-transition](./vpc-routing-transition.md) › **show**_

## NAME

nico-admin-cli-vpc-routing-transition-show - Show routing-profile
transition state and history

## SYNOPSIS

**nico-admin-cli vpc routing-transition show** \[**--vpc-id**\]
\[**--active-only**\] \[**--extended**\] \[**--sort-by**\]
\[**-h**\|**--help**\] \[*ID*\]

## DESCRIPTION

Show routing-profile transition state and history

## OPTIONS

**--vpc-id** *\<VPC_ID\>*  
Filter transition history by VPC ID

**--active-only**  
Show only transitions retaining both VNI leases

**--extended**  
Extended result output.

This used by measured boot, where basic output contains just what you
probably care about, and "extended" output also dumps out all the
internal UUIDs that are used to associate instances.

**--sort-by** *\<SORT_BY\>* \[default: primary-id\]  
Sort output by specified field  

  
*Possible values:*

> - primary-id: Sort by the primary ID
>
> - state: Sort by state

**-h**, **--help**  
Print help (see a summary with -h)

\[*ID*\]  
Optional transition operation ID

## Examples

```sh
nico-admin-cli vpc routing-transition show
nico-admin-cli vpc routing-transition show abcdef01-2345-6789-abcd-ef0123456789
nico-admin-cli vpc routing-transition show --vpc-id 12345678-1234-5678-90ab-cdef01234567
nico-admin-cli vpc routing-transition show --active-only
```

---

**See also:** [Network commands](../../network.md) · [CLI reference index](../../README.md)
