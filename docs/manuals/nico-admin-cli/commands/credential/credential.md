# `nico-admin-cli credential`

_[Hardware commands](../../hardware.md) › **credential**_

## NAME

nico-admin-cli-credential - Credential related handling

## SYNOPSIS

**nico-admin-cli credential** \[**--extended**\] \[**--sort-by**\]
\[**-h**\|**--help**\] \<*subcommands*\>

## DESCRIPTION

Credential related handling

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

## Subcommands

| Subcommand | Description |
|---|---|
| [`add-ufm`](./credential-add-ufm.md) | Add UFM credential |
| [`delete-ufm`](./credential-delete-ufm.md) | Delete UFM credential |
| [`generate-ufm-cert`](./credential-generate-ufm-cert.md) | Generate UFM credential |
| [`add-bmc`](./credential-add-bmc.md) | Add BMC credentials |
| [`delete-bmc`](./credential-delete-bmc.md) | Delete BMC credentials |
| [`add-uefi`](./credential-add-uefi.md) | Add site-wide DPU UEFI default credential (NOTE: this parameter can be set only once) |
| [`add-host-factory-default`](./credential-add-host-factory-default.md) | Add manufacturer factory default BMC user/pass for a given vendor |
| [`add-dpu-factory-default`](./credential-add-dpu-factory-default.md) | Add manufacturer factory default BMC user/pass for the DPUs |
| [`add-nmx-m`](./credential-add-nmx-m.md) | Add NmxM credentials |
| [`delete-nmx-m`](./credential-delete-nmx-m.md) | Delete NmxM credentials |
| [`bgp`](./credential-bgp.md) | Manage leaf BGP passwords |

---

**See also:** [Hardware commands](../../hardware.md) · [CLI reference index](../../README.md)
