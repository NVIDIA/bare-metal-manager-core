pub struct EfiX64;
impl BootArchitecture for EfiX64 {
    fn name(&self) -> &str {
        "x64 UEFI"
    }

    fn efi(&self) -> bool {
        true
    }

    fn arm(&self) -> bool {
        false
    }

    fn pxe(&self) -> bool {
        true
    }

    fn filename(&self) -> String {
        String::from("ipxe.efi")
    }
}
