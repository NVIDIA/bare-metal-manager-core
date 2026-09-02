# `nico-admin-cli vpc routing-transition begin`

_[Network commands](../../network.md) › [vpc](./vpc.md) › [routing-transition](./vpc-routing-transition.md) › **begin**_

## NAME

nico-admin-cli-vpc-routing-transition-begin - Reserve a target VNI and
cut the VPC over while retaining rollback

## SYNOPSIS

**nico-admin-cli vpc routing-transition begin** \[**--vni**\]
\[**--id**\] \[**--if-vpc-version-match**\] \<**--reason**\>
\[**--adopt-existing-target-allocation**\] \[**--extended**\]
\[**--sort-by**\] \[**-h**\|**--help**\] \<*VPC_ID*\>
\<*TARGET_ROUTING_PROFILE_TYPE*\>

## DESCRIPTION

Reserve a target VNI and cut the VPC over while retaining rollback

## OPTIONS

**--vni** *\<VNI\>*  
Exact target VNI; omit for automatic allocation

**--id** *\<ID\>*  
Client operation ID; omit to generate a new idempotency key

**--if-vpc-version-match** *\<IF_VPC_VERSION_MATCH\>*  
Expected VPC version; omit to read the current version immediately
before begin

**--reason** *\<REASON\>*  
Operator change reason (required for the audit record)

**--adopt-existing-target-allocation**  
Adopt the exact --vni already allocated to this VPC (requires --vni)

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

\<*VPC_ID*\>  
VPC to transition

\<*TARGET_ROUTING_PROFILE_TYPE*\>  
Target named routing profile

## Examples

```sh
nico-admin-cli --cloud-unsafe-op=my_username vpc routing-transition begin 12345678-1234-5678-90ab-cdef01234567 EXTERNAL --reason 'approved migration'
nico-admin-cli --cloud-unsafe-op=my_username vpc routing-transition begin 12345678-1234-5678-90ab-cdef01234567 EXTERNAL --vni 51000 --reason 'approved migration'
nico-admin-cli --cloud-unsafe-op=my_username vpc routing-transition begin 12345678-1234-5678-90ab-cdef01234567 EXTERNAL --vni 51000 --adopt-existing-target-allocation --reason 'recover prepared lease'
```

---

**See also:** [Network commands](../../network.md) · [CLI reference index](../../README.md)
