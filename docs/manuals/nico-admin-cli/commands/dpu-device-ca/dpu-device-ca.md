# `nico-admin-cli dpu-device-ca`

_[Hardware commands](../../hardware.md) › **dpu-device-ca**_

## NAME

nico-admin-cli-dpu-device-ca - Manage DPU device-identity (BlueField
IRoT) CA certificates

## SYNOPSIS

**nico-admin-cli dpu-device-ca** \[**--extended**\] \[**--sort-by**\]
\[**-h**\|**--help**\] \<*subcommands*\>

## DESCRIPTION

Manage DPU device-identity (BlueField IRoT) CA certificates

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

## Subcommands

| Subcommand | Description |
|---|---|
| [`show`](./dpu-device-ca-show.md) | Show all DPU device (BlueField IRoT) CA certificates |
| [`delete`](./dpu-device-ca-delete.md) | Delete a DPU device CA certificate with a given id |
| [`add`](./dpu-device-ca-add.md) | Add a DPU device CA certificate encoded in DER/CER/PEM format from a file |

---

**See also:** [Hardware commands](../../hardware.md) · [CLI reference index](../../README.md)
