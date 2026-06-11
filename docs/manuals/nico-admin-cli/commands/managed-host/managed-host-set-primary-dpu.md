# `nico-admin-cli managed-host set-primary-dpu`

_[Hardware commands](../../hardware.md) › [managed-host](./managed-host.md) › **set-primary-dpu**_

## NAME

nico-admin-cli-managed-host-set-primary-dpu - Set the primary DPU for
the managed host

## SYNOPSIS

**nico-admin-cli managed-host set-primary-dpu** \[**--reboot**\]
\[**--extended**\] \[**--sort-by**\] \[**-h**\|**--help**\]
\<*HOST_MACHINE_ID*\> \<*DPU_MACHINE_ID*\>

## DESCRIPTION

Set the primary DPU for the managed host

## OPTIONS

**--reboot**  
Reboot the host after the update

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

\<*HOST_MACHINE_ID*\>  
ID of the host machine

\<*DPU_MACHINE_ID*\>  
ID of the DPU machine to make primary

## Examples

```sh
nico-admin-cli managed-host set-primary-dpu 12345678-1234-5678-90ab-cdef01234567 abcdef01-2345-6789-abcd-ef0123456789
nico-admin-cli managed-host set-primary-dpu 12345678-1234-5678-90ab-cdef01234567 abcdef01-2345-6789-abcd-ef0123456789 --reboot
```

---

**See also:** [Hardware commands](../../hardware.md) · [CLI reference index](../../README.md)
