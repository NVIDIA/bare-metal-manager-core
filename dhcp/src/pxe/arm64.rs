pub struct Arm64;
impl BootArchitecture for Arm64 {
    fn name(&self) -> &str {
        "ARM 64-bit UEFI"
    }

    fn efi(&self) -> bool {
        true
    }

    fn arm(&self) -> bool {
        true
    }

    fn pxe(&self) -> bool {
        true
    }

    fn filename(&self) -> String {
        String::from("ipxe.efi")
    }
}
