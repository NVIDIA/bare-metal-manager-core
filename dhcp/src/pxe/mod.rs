mod arm64;
mod bios_x86;
mod efi_x64;

use std::fmt::Display;

pub use arm64::Arm64;
pub use bios_x86::BiosX86;
pub use efi_x64::EfiX64;

pub trait BootArchitecture {
    fn name(&self) -> &str;
    fn efi(&self) -> bool;
    fn arm(&self) -> bool;
    fn pxe(&self) -> bool;
    fn filename(&self) -> String;
}

pub enum Architectures {
    BiosX86(BiosX86),
    EfiX64(EfiX64),
    Arm64(Arm64),
}

impl Display for dyn BootArchitecture {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} (filename: {})", self.name(), self.filename())
    }
}

impl Architectures {
    pub fn find(pxe_id: u16) -> Option<Box<dyn BootArchitecture>> {
        match pxe_id {
            0x0 => Some(Box::new(BiosX86)),
            0x8 => Some(Box::new(EfiX64)),
            0xb => Some(Box::new(Arm64)),
            _ => None,
        }
    }
}

/*
0x00 0x00,x86 BIOS,[RFC5970][RFC4578]
0x00 0x01,NEC/PC98 (DEPRECATED),[RFC5970][RFC4578]
0x00 0x02,Itanium,[RFC5970][RFC4578]
0x00 0x03,DEC Alpha (DEPRECATED),[RFC5970][RFC4578]
0x00 0x04,Arc x86 (DEPRECATED),[RFC5970][RFC4578]
0x00 0x05,Intel Lean Client (DEPRECATED),[RFC5970][RFC4578]
0x00 0x06,x86 UEFI,[RFC5970][RFC4578]
0x00 0x07,x64 UEFI,[RFC5970][RFC4578]
0x00 0x08,EFI Xscale (DEPRECATED),[RFC5970][RFC4578]
0x00 0x09,EBC,[RFC5970][RFC4578]
0x00 0x0a,ARM 32-bit UEFI,[RFC5970]
0x00 0x0b,ARM 64-bit UEFI,[RFC5970]
0x00 0x0c,PowerPC Open Firmware,[Thomas_Huth]
0x00 0x0d,PowerPC ePAPR,[Thomas_Huth]
0x00 0x0e,POWER OPAL v3,[Jeremy_Kerr]
0x00 0x0f,x86 uefi boot from http,[Samer_El-Haj-Mahmoud]
0x00 0x10,x64 uefi boot from http,[Samer_El-Haj-Mahmoud]
0x00 0x11,ebc boot from http,[Samer_El-Haj-Mahmoud]
0x00 0x12,arm uefi 32 boot from http,[Samer_El-Haj-Mahmoud]
0x00 0x13,arm uefi 64 boot from http,[Samer_El-Haj-Mahmoud]
0x00 0x14,pc/at bios boot from http,[Samer_El-Haj-Mahmoud]
0x00 0x15,arm 32 uboot,[Joseph_Shifflett]
0x00 0x16,arm 64 uboot,[Joseph_Shifflett]
0x00 0x17,arm uboot 32 boot from http,[Joseph_Shifflett]
0x00 0x18,arm uboot 64 boot from http,[Joseph_Shifflett]
0x00 0x19,RISC-V 32-bit UEFI,[Dong_Wei]
0x00 0x1a,RISC-V 32-bit UEFI boot from http,[Dong_Wei]
0x00 0x1b,RISC-V 64-bit UEFI,[Dong_Wei]
0x00 0x1c,RISC-V 64-bit UEFI boot from http,[Dong_Wei]
0x00 0x1d,RISC-V 128-bit UEFI,[Dong_Wei]
0x00 0x1e,RISC-V 128-bit UEFI boot from http,[Dong_Wei]
0x00 0x1f,s390 Basic,[Viktor_Mihajlovski]
0x00 0x20,s390 Extended,[Viktor_Mihajlovski]
0x00 0x21,MIPS 32-bit UEFI,[Jiading_Zhang]
0x00 0x22,MIPS 64-bit UEFI,[Jiading_Zhang]
0x00 0x23,Sunway 32-bit UEFI,[Jiading_Zhang]
0x00 0x24,Sunway 64-bit UEFI,[Jiading_Zhang]
0x00 0x25,LoongArch 32-bit UEFI,[LI_Chao][https://loongson.github.io/LoongArch-Documentation/README-EN.html][https://github.com/loongson/LoongArch-Documentation]
0x00 0x26,LoongArch 32-bit UEFI boot from http,[LI_Chao][https://loongson.github.io/LoongArch-Documentation/README-EN.html][https://github.com/loongson/LoongArch-Documentation]
0x00 0x27,LoongArch 64-bit UEFI,[LI_Chao][https://loongson.github.io/LoongArch-Documentation/README-EN.html][https://github.com/loongson/LoongArch-Documentation]
0x00 0x28,LoongArch 64-bit UEFI boot from http,[LI_Chao][https://loongson.github.io/LoongArch-Documentation/README-EN.html][https://github.com/loongson/LoongArch-Documentation]
0x00 0x29-0xff 0xff,Unassigned,
*/
