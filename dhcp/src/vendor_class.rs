use std::{fmt::Display, str::FromStr};

#[derive(Debug, PartialEq)]
pub enum MachineClientClass {
    PXEClient,
    HTTPClient,
}

#[derive(Debug, PartialEq)]
pub enum MachineArchitecture {
    BiosX86,
    EfiX64,
    Arm64,
}

#[derive(Debug)]
pub struct VendorClass {
    pub client_type: MachineClientClass,
    pub client_architecture: MachineArchitecture,
}

#[derive(Debug)]
pub enum VendorClassParseError {
    InvalidFormat,
    UnsupportedClientType,
    UnsupportedArchitecture,
}

impl FromStr for MachineArchitecture {
    type Err = VendorClassParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            // When a DPU (and presumably other hardware) has an OS
            // the vendor class no longer is a UEFI vendor
            "aarch64" => Ok(MachineArchitecture::Arm64),
            _ => {
                match s.parse() {
                    // This is base 10 represented by the long vendor class
                    Ok(0) => Ok(MachineArchitecture::BiosX86),
                    Ok(7) => Ok(MachineArchitecture::EfiX64),
                    Ok(11) => Ok(MachineArchitecture::Arm64),
                    Ok(16) => Ok(MachineArchitecture::EfiX64), // HTTP version
                    Ok(19) => Ok(MachineArchitecture::Arm64),  // HTTP version
                    Ok(_) => Err(VendorClassParseError::UnsupportedArchitecture), // Unknown
                    Err(_) => Err(VendorClassParseError::InvalidFormat), // Better Error
                }
            }
        }
    }
}

#[allow(dead_code)]
impl VendorClass {
    pub fn pxe(&self) -> bool {
        self.client_type == MachineClientClass::PXEClient
    }

    pub fn http(&self) -> bool {
        self.client_type == MachineClientClass::HTTPClient
    }

    pub fn arm(&self) -> bool {
        self.client_architecture == MachineArchitecture::Arm64
    }

    pub fn x64(&self) -> bool {
        self.client_architecture == MachineArchitecture::EfiX64
    }

    pub fn is_it_modern(&self) -> bool {
        self.http() && self.arm()
    }
}

impl Display for MachineClientClass {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            match self {
                Self::PXEClient => "PXE Client",
                Self::HTTPClient => "HTTP Client",
            }
        )
    }
}

impl Display for VendorClass {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} ({})", self.client_architecture, self.client_type)
    }
}

impl Display for MachineArchitecture {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            match self {
                Self::Arm64 => "ARM 64-bit UEFI",
                Self::EfiX64 => "x64 UEFI",
                Self::BiosX86 => "x86 BIOS",
            }
        )
    }
}

impl FromStr for MachineClientClass {
    type Err = VendorClassParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "PXEClient" => Ok(Self::PXEClient),
            "HTTPClient" => Ok(Self::HTTPClient),
            "nvidia-bluefield-dpu" => Ok(Self::PXEClient),
            _ => Err(VendorClassParseError::UnsupportedClientType),
        }
    }
}
///
/// Convert a string of the form A:B:C:D... to Self
///
impl FromStr for VendorClass {
    type Err = VendorClassParseError;

    fn from_str(vendor_class: &str) -> Result<Self, Self::Err> {
        if vendor_class.contains(':') {
            // this is the UEFI version
            let parts: Vec<&str> = vendor_class.split(':').collect();
            match parts.len() {
                5 => Ok(VendorClass {
                    client_type: parts[0].parse()?,
                    client_architecture: parts[2].parse()?,
                }),
                _ => Err(VendorClassParseError::InvalidFormat),
            }
        } else if vendor_class.contains(' ') {
            // This is the OS (bluefield so far, maybe host OS's too)
            let parts: Vec<&str> = vendor_class.split(' ').collect();
            match parts.len() {
                2 =>  Ok(VendorClass {
                    client_type: parts[0].parse()?,
                    client_architecture: parts[1].parse()?,
                }),
                _ => Err(VendorClassParseError::InvalidFormat),
            }
        } else {
            Err(VendorClassParseError::InvalidFormat)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_is_pxe_capable() {
        let vc: VendorClass = "PXEClient:Arch:00007:UNDI:003000".parse().unwrap();

        assert!(vc.pxe());
        assert!(!vc.http());
    }

    #[test]
    fn is_it_arm_non_uefi() {
        let vc: VendorClass = "nvidia-bluefield-dpu aarch64".parse().unwrap();
        assert!(vc.arm());
    }

    #[test]
    fn is_it_arm() {
        let vc: VendorClass = "PXEClient:Arch:00011:UNDI:003000".parse().unwrap();
        assert!(vc.arm());
    }

    #[test]
    fn is_it_not_modern() {
        let vc: VendorClass = "PXEClient:Arch:00007:UNDI:003000".parse().unwrap();
        assert!(!vc.is_it_modern());
    }

    #[test]
    fn is_it_modern() {
        let vc: VendorClass = "HTTPClient:Arch:00011:UNDI:003000".parse().unwrap();
        assert!(vc.is_it_modern());
    }

    #[test]
    fn it_is_http_capable() {
        let vc: VendorClass = "HTTPClient:Arch:00016:UNDI:003001".parse().unwrap();
        assert!(vc.http());
        assert!(!vc.pxe());
    }

    #[test]
    fn it_is_http_and_not_arm() {
        let vc: VendorClass = "HTTPClient:Arch:00016:UNDI:003001".parse().unwrap();
        assert!(vc.http());
        assert!(vc.x64());
    }

    #[test]
    fn it_fails_on_unknown_client() {
        let vc: Result<VendorClass, VendorClassParseError> =
            "NothingClient:Arch:00007:UNDI:X".parse();
        assert!(matches!(vc, Err(_)));
    }

    #[test]
    fn it_fails_on_unknown_arch() {
        let vc: Result<VendorClass, VendorClassParseError> = "HTTPClient:Arch:01007:UNDI:X".parse();
        assert!(matches!(vc, Err(_)));
    }

    #[test]
    fn it_formats_the_parser_armuefi() {
        let vc: VendorClass = "HTTPClient:Arch:00011:UNDI:003000".parse().unwrap();
        assert_eq!(vc.to_string(), "ARM 64-bit UEFI (HTTP Client)");
    }

    #[test]
    fn it_formats_the_parser_legacypxe() {
        let vc: VendorClass = "PXEClient:Arch:00000:UNDI:003000".parse().unwrap();
        assert_eq!(vc.to_string(), "x86 BIOS (PXE Client)");
    }
}
