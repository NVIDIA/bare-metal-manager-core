# `nico-admin-cli dpu-device-ca show`

_[Hardware commands](../../hardware.md) › [dpu-device-ca](./dpu-device-ca.md) › **show**_

## NAME

nico-admin-cli-dpu-device-ca-show - Show all DPU device (BlueField IRoT)
CA certificates

## SYNOPSIS

**nico-admin-cli dpu-device-ca show** \[**--extended**\]
\[**--sort-by**\] \[**-h**\|**--help**\]

## DESCRIPTION

Show all DPU device (BlueField IRoT) CA certificates

## OPTIONS

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

---

**See also:** [Hardware commands](../../hardware.md) · [CLI reference index](../../README.md)
