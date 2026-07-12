# `nico-admin-cli boot-interface set`

_[Hardware commands](../../hardware.md) › [boot-interface](./boot-interface.md) › **set**_

## NAME

nico-admin-cli-boot-interface-set - Set the boot interface for a machine
(promotes it to the primary interface)

## SYNOPSIS

**nico-admin-cli boot-interface set** \[**--reboot**\]
\[**--extended**\] \[**--sort-by**\] \[**-h**\|**--help**\]
\<*MACHINE*\> \<*INTERFACE*\>

## DESCRIPTION

Make an interface the boot interface for a machine by promoting it to
the primary interface, the designation every boot flow acts on. This
is the same operation as \`managed-host set-primary-interface\`: the BMC
boot order is updated first, then the primary flag moves in the
database. The interface can be named by machine-interface UUID or by MAC
address; a MAC must match exactly one managed interface row on the
machine.

## OPTIONS

**--reboot**  
Reboot the host after the update

**--extended**  
Extended result output.

This used by measured boot, where basic output contains just what you
probably care about, and "extended" output also dumps out all the
internal UUIDs that are used to associate instances.

**--sort-by** *\<SORT_BY\>* \[default: primary-id\]  
Sort output by specified field  

  
*Possible values:*

> - primary-id: Sort by the primary id
>
> - state: Sort by state

**-h**, **--help**  
Print help (see a summary with -h)

\<*MACHINE*\>  
The machine whose boot interface to set

\<*INTERFACE*\>  
The interface to boot from: a machine-interface UUID or a MAC address

## Examples

```sh
nico-admin-cli boot-interface set 12345678-1234-5678-90ab-cdef01234567 00:11:22:33:44:55
nico-admin-cli boot-interface set 12345678-1234-5678-90ab-cdef01234567 abcdef01-2345-6789-abcd-ef0123456789
nico-admin-cli boot-interface set 12345678-1234-5678-90ab-cdef01234567 00:11:22:33:44:55 --reboot
```

---

**See also:** [Hardware commands](../../hardware.md) · [CLI reference index](../../README.md)
