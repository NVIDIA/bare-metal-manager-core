#[derive(PartialEq)]
pub enum AbsentSubnetStrategy {
    Fail,
    Ignore,
}

pub enum AddressSelectionStrategy<T> {
    Empty,
    Static(T),
    Automatic(AbsentSubnetStrategy),
}
