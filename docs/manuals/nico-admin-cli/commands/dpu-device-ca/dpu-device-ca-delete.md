# `nico-admin-cli dpu-device-ca delete`

_[Hardware commands](../../hardware.md) › [dpu-device-ca](./dpu-device-ca.md) › **delete**_

## NAME

nico-admin-cli-dpu-device-ca-delete - Delete a DPU device CA certificate
with a given id

## SYNOPSIS

**nico-admin-cli dpu-device-ca delete** \<**-c**\|**--ca-id**\>
\[**--extended**\] \[**--sort-by**\] \[**-h**\|**--help**\]

## DESCRIPTION

Delete a DPU device CA certificate with a given id

## OPTIONS

**-c**, **--ca-id** *\<CA_ID\>*  
DPU device CA id obtained from the show command

**--extended**  
Extended result output.

This used by measured boot, where basic output contains just what you
probably care about, and "extended" output also dumps out all the
internal UUIDs that are used to associate instances.

**--sort-by** *\<SORT_BY\>* \[default: primary-id\]  
Sort output by specified field  

  
*Possible values:*

- primary-id: Sort by the primary id

- state: Sort by state

**-h**, **--help**  
Print help (see a summary with -h)

## Examples

```sh
nico-admin-cli dpu-device-ca delete --ca-id 42
```

---

**See also:** [Hardware commands](../../hardware.md) · [CLI reference index](../../README.md)
