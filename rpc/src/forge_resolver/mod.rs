use std::fs::File;
use std::io;
use std::io::Read;
use std::path::Path;

pub mod resolver;

pub fn read_resolv_conf<P: AsRef<Path>>(path: P) -> Result<resolv_conf::Config, io::Error> {
    let mut data = String::new();
    let mut file = File::open(&path).map_err(|_| {
        io::Error::new(
            io::ErrorKind::Other,
            eyre::eyre!(
                "Unable to read resolv.conf at {:?}",
                path.as_ref().file_name()
            ),
        )
    })?;

    file.read_to_string(&mut data)?;
    parse_resolv_conf(&data)
}

pub fn parse_resolv_conf<T: AsRef<[u8]>>(data: T) -> Result<resolv_conf::Config, io::Error> {
    resolv_conf::Config::parse(&data).map_err(|e| {
        io::Error::new(
            io::ErrorKind::Other,
            format!("Error parsing resolv.conf: {e}"),
        )
    })
}
