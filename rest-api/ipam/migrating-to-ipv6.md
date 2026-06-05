# IPv6 Support for metal-stack

Two years ago, when we started to implement metal-stack, we first decided to rely on an external tool to do all the hard IP address management.
For this purpose we used [netbox](https://github.com/netbox-community/netbox) from digitalocean.
To talk to netbox we also implemented our own go library, which was not available back then, because all of metal-stack is written in go.

It turned out that netbox serves well for our purpose: creating networks, acquiring IPs and releasing them work as expected but was way to slow.
We also found that their API forced us to make a lot of calls for one single purpose.

Because "speed and simplicity" was one of our main goals during the development of metal-stack we decided to implement our own IPAM (IP Address Management) and so [go-ipam](https://github.com/metal-stack/go-ipam) was born.

## The Beginning

go-ipam should only serve the IPAM requirements from metal-stack and these are:

- managing prefixes (a prefix is a network with a given bitlength or mask)
- managing child prefixes, this is required to get a prefix out of a bigger prefix
- acquisition and release of IPs from a specified prefix

The interface of go-ipam is simple, we have two structs, IP and Prefix:

```go
type IP struct {
    IP           netaddr.IP
    ParentPrefix string
}

type Prefix struct {
    Cidr         string
    ParentCidr   string
}
```

And the visible interface is:

```go
type Ipamer interface {
    // NewPrefix create a new Prefix from a string notation.
    NewPrefix(cidr string) (*Prefix, error)
    // DeletePrefix delete a Prefix from a string notation.
    // If the Prefix is not found an NotFoundError is returned.
    DeletePrefix(cidr string) (*Prefix, error)
    // AcquireChildPrefix will return a Prefix with a smaller length from the given Prefix.
    AcquireChildPrefix(parentCidr string, length uint8) (*Prefix, error)
    // ReleaseChildPrefix will mark this child Prefix as available again.
    ReleaseChildPrefix(child *Prefix) error
    // PrefixFrom will return a known Prefix.
    PrefixFrom(cidr string) *Prefix
    // AcquireSpecificIP will acquire given IP and mark this IP as used, if already in use, return nil.
    // If specificIP is empty, the next free IP is returned.
    // If there is no free IP an NoIPAvailableError is returned.
    AcquireSpecificIP(prefixCidr, specificIP string) (*IP, error)
    // AcquireIP will return the next unused IP from this Prefix.
    AcquireIP(prefixCidr string) (*IP, error)
    // ReleaseIP will release the given IP for later usage and returns the updated Prefix.
    // If the IP is not found an NotFoundError is returned.
    ReleaseIP(ip *IP) (*Prefix, error)
    // ReleaseIPFromPrefix will release the given IP for later usage.
    // If the Prefix or the IP is not found an NotFoundError is returned.
    ReleaseIPFromPrefix(prefixCidr, ip string) error
}
```

With this we were able to do what we expected: to create a prefix and acquire a free IP.
After the IP is not used anymore, we can release the IP, and if no IP is left in the prefix we will release the prefix as well.
The following snippet shows how.

```go
    ipamer := New()
    prefix, err := ipamer.NewPrefix("192.168.0.0/24")
    if err != nil {
        panic(err)
    }
    ip1, err := ipamer.AcquireIP(prefix.Cidr)
    if err != nil {
        panic(err)
    }
    fmt.Printf("Super Prefix  : %s\n", prefix)
    fmt.Printf("Super Prefix IP1 : %s\n", ip1.IP.String())
    fmt.Printf("Super Prefix IP1 Parent : %s\n", ip1.ParentPrefix)
    // Output:
    // Super Prefix  : 192.168.0.0/24
    // Super Prefix IP1 : 192.168.0.1
    // Super Prefix IP1 Parent : 192.168.0.0/24
    _, err = ipamer.ReleaseIP(ip1)
    if err != nil {
        panic(err)
    }
    _, err = ipamer.DeletePrefix(prefix.Cidr)
    if err != nil {
        panic(err)
    }
```

With this implementation we were able to do all IPAM operations in a matter of milliseconds instead of 10s of seconds when using netbox.
So we ripped out netbox from metal-api and used our own go-ipam since then.

## Open Issues

As we wanted to be fast during the implementation of go-ipam, we skipped some ugly parts. We were not able to implement two major things:

- [IPv6](https://en.wikipedia.org/wiki/IPv6)
- Child prefixes with variable bitlength or mask

Both features require complicated and well tested algorithms for IP addresses. We skipped this effort for the time being.
We also did not have an urgent requirement to support IPv6 because kubernetes was at version 1.13 and IPv6 support was not implemented either, see: [Kubernetes warms up to ipv6](https://thenewstack.io/kubernetes-warms-up-to-ipv6/).
But we where aware that at a later point in time we have to come back and dive deep into IPv6.

The missing support for variable bitlength for child prefixes was another story. Missing this feature forced us to create several networks "by hand" for some cases.

## The Solution

As time went by, we discovered the excellent work from the people behind [tailscale](https://tailscale.com).
They implemented an alternative network manipulation library for go called [inet.af/netaddr](https://github.com/inetaf/netaddr).
In contrast to the `net` package in the go standard library, `inet.af/netaddr` has a more convenient and usable API to manipulate network objects:

The most important are `netaddr.IP.Next()` and `netaddr.IP.Contains`, with them it was a snap to implement `AcquireIP` IPv6 compatible. It took us less than 4 hours to make this work and to add additional tests and all passes. Hurray!

By looking into `inet.af/netaddr` we stumbled over some other functions which would enable us to solve the child prefix creation for IPv6 as well. First we implemented the required code into go-ipam, but this would probably also be useful for users of `inet.af/netaddr` as well. We created a pull-request which got finally merged: [#61](https://github.com/inetaf/netaddr/pull/61).

With this all in place we gained a lot, not only full IPv6 support, but also the ability to create a child prefix out of a prefix with a defined bitlength.

Now we are able to do something like this:

```go
    ipamer := New()
    prefix, err := ipamer.NewPrefix("2001:aabb::/48")
    if err != nil {
        panic(err)
    }
    cp1, err := ipamer.AcquireChildPrefix(prefix.Cidr, 64)
    if err != nil {
        panic(err)
    }
    cp2, err := ipamer.AcquireChildPrefix(prefix.Cidr, 72)
    if err != nil {
        panic(err)
    }
    ip21, err := ipamer.AcquireIP(cp2.Cidr)
    if err != nil {
        panic(err)
    }
    prefix = ipamer.PrefixFrom(prefix.Cidr)
    fmt.Printf("Super Prefix  : %s\n", prefix)
    fmt.Printf("Child Prefix 1: %s\n", cp1)
    fmt.Printf("Child Prefix 2: %s\n", cp2)
    fmt.Printf("Child Prefix 2 IP1: %s\n", ip21.IP)
    // Output:
    // Super Prefix  : 2001:aabb::/48
    // Child Prefix 1: 2001:aabb::/64
    // Child Prefix 2: 2001:aabb:0:1::/72
    // Child Prefix 2 IP1: 2001:aabb:0:1::1
```

After this work which was done under the hood of `go-ipam`, we still have the same API which makes migration of the dependent projects easy.

### Benchmarks

As it turns out we got even more. Because we switched all network object manipulation from go standard library `net` to `inet.af/netaddr`, all of our functions got way faster with less memory consumption. Go comes with fantastic benchmarking built in and we will explain how to get most out of this in a later blog post.

Shown below are the benchmark results before and after using `inet.af/netaddr`

```sh
name                    old time/op    new time/op    delta
NewPrefixMemory-4         3.15µs ± 1%    2.34µs ± 7%   -25.56%  (p=0.016 n=4+5)
NewPrefixPostgres-4       10.3ms ± 6%    10.1ms ±12%      ~     (p=0.686 n=4+4)
NewPrefixCockroach-4      81.1ms ± 5%    80.0ms ± 3%      ~     (p=0.486 n=4+4)
AcquireIPMemory-4         4.63µs ±12%    3.90µs ± 1%   -15.91%  (p=0.016 n=5+4)
AcquireIPPostgres-4       12.6ms ± 9%    13.4ms ± 7%      ~     (p=0.222 n=5+5)
AcquireIPCockroach-4      79.6ms ± 6%    85.2ms ± 9%      ~     (p=0.095 n=5+5)
AcquireChildPrefix1-4     31.6µs ±12%     8.1µs ± 7%   -74.43%  (p=0.008 n=5+5)
AcquireChildPrefix2-4     93.8µs ±17%     8.3µs ±10%   -91.17%  (p=0.008 n=5+5)
AcquireChildPrefix3-4     1.56ms ± 7%    0.01ms ± 5%   -99.51%  (p=0.008 n=5+5)
AcquireChildPrefix4-4     9.79ms ±37%    0.01ms ± 4%   -99.92%  (p=0.008 n=5+5)
AcquireChildPrefix5-4     82.4ms ± 6%     0.0ms ±34%   -99.99%  (p=0.008 n=5+5)
AcquireChildPrefix6-4     10.9µs ±10%     7.9µs ± 5%   -27.17%  (p=0.008 n=5+5)
AcquireChildPrefix7-4     15.0µs ± 6%     7.7µs ± 2%   -48.61%  (p=0.008 n=5+5)
AcquireChildPrefix8-4     30.2µs ± 0%     7.5µs ± 1%   -75.04%  (p=0.016 n=4+5)
AcquireChildPrefix9-4     97.2µs ± 9%     7.7µs ± 3%   -92.10%  (p=0.008 n=5+5)
AcquireChildPrefix10-4     360µs ± 7%       8µs ± 1%   -97.91%  (p=0.008 n=5+5)
PrefixOverlapping-4       1.65µs ±12%    0.34µs ± 1%   -79.25%  (p=0.008 n=5+5)
```

As you can see, we are faster all over the place by a large margin.

## Next Steps

go-ipam is the foundation for IP address management in metal-stack and is IPv6 ready now. We are currently in the process of make all dependent parts IPv6 aware as well. This journey will be ready in the next couple of weeks.

The following metal-stack components need adoption or at least testing (probably incomplete):

- [metal-api](https://github.com/metal-stack/metal-api/pull/152)
- [metalctl](https://github.com/metal-stack/metalctl/pull/72)
- [metal-networker](https://github.com/metal-stack/metal-networker/pull/42)
- [metal-images](https://github.com/metal-stack/metal-images/pull/70)
- [mini-lab](https://github.com/metal-stack/mini-lab/tree/ipv6)
- [firewall-controller](https://github.com/metal-stack/firewall-controller)
