pub fn capacity_string(size_mb: u64) -> String {
    match byte_unit::Byte::from_u64_with_unit(size_mb, byte_unit::Unit::MiB) {
        Some(byte) => byte
            .get_appropriate_unit(byte_unit::UnitType::Binary)
            .to_string(),
        None => "Invalid".to_string(),
    }
}
