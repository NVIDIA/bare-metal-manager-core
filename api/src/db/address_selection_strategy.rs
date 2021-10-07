pub type IgnoreAbsentSubnet = bool;

pub enum AddressSelectionStrategy<T> {
    Empty,
    Static(T),
    Automatic(IgnoreAbsentSubnet),
}
