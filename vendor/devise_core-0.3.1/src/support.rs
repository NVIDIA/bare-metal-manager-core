#![allow(non_upper_case_globals)]

bitflags! {
    #[derive(Default)]
    pub struct Support: u8 {
        const None            = 0b0000_000;
        const Type            = 0b0000_001;
        const Lifetime        = 0b0000_010;
        const Const           = 0b0000_100;
        const AllGeneric      = 0b0000_111;
        const TupleStruct     = 0b0001_000;
        const NamedStruct     = 0b0010_000;
        const Struct          = 0b0011_000;
        const Enum            = 0b0100_000;
        const Union           = 0b1000_000;
        const AllData         = 0b1111_000;
        const All             = 0b1111_111;
    }
}
