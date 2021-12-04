use super::*;
pub struct BiosX86;
impl BootArchitecture for BiosX86 {
    fn name(&self) -> &str {
        "x86 BIOS"
    }

    fn efi(&self) -> bool {
        false
    }

    fn arm(&self) -> bool {
        false
    }

    fn pxe(&self) -> bool {
        true
    }

    fn filename(&self) -> String {
        String::from("ipxe.kpxe")
    }
}
