# `nico-admin-cli domain create`

_[Network commands](../../network.md) › [domain](./domain.md) › **create**_

## NAME

nico-admin-cli-domain-create - Create Domain

## SYNOPSIS

**nico-admin-cli domain create** \<**--name**\> \[**--extended**\]
\[**--sort-by**\] \[**-h**\|**--help**\]

## DESCRIPTION

Create Domain

## OPTIONS

**--name** *\<NAME\>*  
Name of the DNS domain to create

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

**-h**, **--help**  
Print help (see a summary with -h)

## Examples

```sh
nico-admin-cli domain create --name site.example.com
```

---

**See also:** [Network commands](../../network.md) · [CLI reference index](../../README.md)
