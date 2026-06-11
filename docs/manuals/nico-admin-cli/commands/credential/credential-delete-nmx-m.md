# `nico-admin-cli credential delete-nmx-m`

_[Hardware commands](../../hardware.md) › [credential](./credential.md) › **delete-nmx-m**_

## NAME

nico-admin-cli-credential-delete-nmx-m - Delete NmxM credentials

## SYNOPSIS

**nico-admin-cli credential delete-nmx-m** \<**--username**\>
\[**--extended**\] \[**--sort-by**\] \[**-h**\|**--help**\]

## DESCRIPTION

Delete NmxM credentials

## OPTIONS

**--username** *\<USERNAME\>*  
NmxM url

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
nico-admin-cli credential delete-nmx-m --username admin
```

---

**See also:** [Hardware commands](../../hardware.md) · [CLI reference index](../../README.md)
