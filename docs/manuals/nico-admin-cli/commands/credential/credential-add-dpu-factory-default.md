# `nico-admin-cli credential add-dpu-factory-default`

_[Hardware commands](../../hardware.md) › [credential](./credential.md) › **add-dpu-factory-default**_

## NAME

nico-admin-cli-credential-add-dpu-factory-default - Add manufacturer
factory default BMC user/pass for the DPUs

## SYNOPSIS

**nico-admin-cli credential add-dpu-factory-default** \<**--username**\>
\<**--password**\> \[**--extended**\] \[**--sort-by**\]
\[**-h**\|**--help**\]

## DESCRIPTION

Add manufacturer factory default BMC user/pass for the DPUs

## OPTIONS

**--username** *\<USERNAME\>*  
Default username: root, ADMIN, etc

**--password** *\<PASSWORD\>*  
DPU manufacturer default password

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
nico-admin-cli credential add-dpu-factory-default --username admin --password mypassword
```

---

**See also:** [Hardware commands](../../hardware.md) · [CLI reference index](../../README.md)
