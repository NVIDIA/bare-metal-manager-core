# `nico-admin-cli managed-host set-primary-interface`

_[Hardware commands](../../hardware.md) › [managed-host](./managed-host.md) › **set-primary-interface**_

## NAME

nico-admin-cli-managed-host-set-primary-interface - Set the primary
interface (boot device) for the managed host

## SYNOPSIS

**nico-admin-cli managed-host set-primary-interface**
\[**--force-reconcile**\] \[**--reboot**\] \[**--extended**\]
\[**--sort-by**\] \[**-h**\|**--help**\] \<*HOST_MACHINE_ID*\>
\<*INTERFACE_ID*\>

## DESCRIPTION

Set the primary interface (boot device) for the managed host

## OPTIONS

**--force-reconcile**  
Request a fresh machine-controller reconciliation even when this
interface is already selected

**--reboot**  
Deprecated compatibility alias; use --force-reconcile with current
servers

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

\<*INTERFACE_ID*\>  
ID of the machine interface to make primary (the boot device)

## Examples

```sh
nico-admin-cli managed-host set-primary-interface 12345678-1234-5678-90ab-cdef01234567 abcdef01-2345-6789-abcd-ef0123456789
nico-admin-cli managed-host set-primary-interface 12345678-1234-5678-90ab-cdef01234567 abcdef01-2345-6789-abcd-ef0123456789 --force-reconcile
```

---

**See also:** [Hardware commands](../../hardware.md) · [CLI reference index](../../README.md)
