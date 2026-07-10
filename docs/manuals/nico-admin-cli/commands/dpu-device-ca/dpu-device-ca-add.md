# `nico-admin-cli dpu-device-ca add`

_[Hardware commands](../../hardware.md) › [dpu-device-ca](./dpu-device-ca.md) › **add**_

## NAME

nico-admin-cli-dpu-device-ca-add - Add a DPU device CA certificate
encoded in DER/CER/PEM format from a file

## SYNOPSIS

**nico-admin-cli dpu-device-ca add** \<**-f**\|**--filename**\>
\[**--extended**\] \[**--sort-by**\] \[**-h**\|**--help**\]

## DESCRIPTION

Add a DPU device CA certificate encoded in DER/CER/PEM format from a
file

## OPTIONS

**-f**, **--filename** *\<FILENAME\>*  
File containing the device root CA certificate (DER/CER/PEM)

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
nico-admin-cli dpu-device-ca add --filename /path/to/bluefield-device-root.pem
```

---

**See also:** [Hardware commands](../../hardware.md) · [CLI reference index](../../README.md)
