# `nico-admin-cli vpc routing-transition`

_[Network commands](../../network.md) › [vpc](./vpc.md) › **routing-transition**_

## NAME

nico-admin-cli-vpc-routing-transition - Manage a staged VPC
routing-profile and VNI transition

## SYNOPSIS

**nico-admin-cli vpc routing-transition** \[**--extended**\]
\[**--sort-by**\] \[**-h**\|**--help**\] \<*subcommands*\>

## DESCRIPTION

Manage a staged VPC routing-profile and VNI transition

## OPTIONS

**--extended**  
Extended result output.

This used by measured boot, where basic output contains just what you
probably care about, and "extended" output also dumps out all the
internal UUIDs that are used to associate instances.

**--sort-by** *\<SORT_BY\>* \[default: primary-id\]  
Sort output by specified field  

  
*Possible values:*

> - primary-id: Sort by the primary ID
>
> - state: Sort by state

**-h**, **--help**  
Print help (see a summary with -h)

## Examples

```sh
nico-admin-cli --cloud-unsafe-op=my_username vpc routing-transition begin 12345678-1234-5678-90ab-cdef01234567 EXTERNAL --reason 'approved migration'
nico-admin-cli --cloud-unsafe-op=my_username vpc routing-transition begin 12345678-1234-5678-90ab-cdef01234567 EXTERNAL --vni 51000 --reason 'approved migration'
nico-admin-cli vpc routing-transition show --active-only
nico-admin-cli --cloud-unsafe-op=my_username vpc routing-transition finalize 87654321-4321-8765-ba09-123456789abc --confirm-converged
```

## Subcommands

| Subcommand | Description |
|---|---|
| [`begin`](./vpc-routing-transition-begin.md) | Reserve a target VNI and cut the VPC over while retaining rollback |
| [`rollback`](./vpc-routing-transition-rollback.md) | Switch a pending cutover back to its retained source endpoint |
| [`recutover`](./vpc-routing-transition-recutover.md) | Switch a rolled-back transition to its retained target again |
| [`finalize`](./vpc-routing-transition-finalize.md) | Release the inactive VNI after out-of-band convergence confirmation |
| [`show`](./vpc-routing-transition-show.md) | Show routing-profile transition state and history |

---

**See also:** [Network commands](../../network.md) · [CLI reference index](../../README.md)
