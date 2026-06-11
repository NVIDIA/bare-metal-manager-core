# `nico-admin-cli machine force-delete`

_[Hardware commands](../../hardware.md) › [machine](./machine.md) › **force-delete**_

## NAME

nico-admin-cli-machine-force-delete - Force delete a machine

## SYNOPSIS

**nico-admin-cli machine force-delete** \<**--machine**\>
\[**-d**\|**--delete-interfaces**\]
\[**-b**\|**--delete-bmc-interfaces**\]
\[**-c**\|**--delete-bmc-credentials**\]
\[**--allow-delete-with-instance**\]
\[**--allow-delete-with-orphaned-dpf-crds**\] \[**--extended**\]
\[**--sort-by**\] \[**-h**\|**--help**\]

## DESCRIPTION

Force delete a machine

## OPTIONS

**--machine** *\<MACHINE\>*  
UUID, IPv4, MAC or hostnmame of the host or DPU machine to delete

**-d**, **--delete-interfaces**  
Delete interfaces. Redeploy kea after deleting machine interfaces.

**-b**, **--delete-bmc-interfaces**  
Delete BMC interfaces. Redeploy kea after deleting machine interfaces.

**-c**, **--delete-bmc-credentials**  
Delete BMC credentials. Only applicable if site explorer has configured
credentials for the BMCs associated with this managed host.

**--allow-delete-with-instance**  
Delete machine with allocated instance. This flag acknowledges
destroying the user instance as well.

**--allow-delete-with-orphaned-dpf-crds**  
Delete machine even if DPF CRDs exist and DPF is disabled at the site
level. This flag acknowledges that orphaned DPF resources may remain

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
nico-admin-cli machine force-delete --machine 12345678-1234-5678-90ab-cdef01234567
nico-admin-cli machine force-delete --machine 12345678-1234-5678-90ab-cdef01234567 --delete-interfaces
```

---

**See also:** [Hardware commands](../../hardware.md) · [CLI reference index](../../README.md)
