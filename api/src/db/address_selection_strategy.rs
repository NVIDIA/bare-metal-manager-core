use std::net::IpAddr;

pub enum AddressSelectionStrategy<'a> {
    Empty,
    Static(&'a [IpAddr]),
    Automatic,
}
