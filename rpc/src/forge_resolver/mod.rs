use crate::forge_resolver::resolver::ResolverError;
use std::fs::File;
use std::io;
use std::io::Read;
use std::path::Path;

pub mod resolver;

pub fn read_resolv_conf<P: AsRef<Path>>(path: P) -> Result<resolv_conf::Config, ResolverError> {
    let mut data = String::new();
    let mut file = File::open(&path)
        .map_err(|_| {
            io::Error::other(eyre::eyre!(
                "Unable to read resolv.conf at {:?}",
                path.as_ref().file_name()
            ))
        })
        .map_err(|e| ResolverError::CouldNotReadResolvConf {
            path: path.as_ref().to_path_buf(),
            error: e,
        })?;

    file.read_to_string(&mut data)
        .map_err(|e| ResolverError::CouldNotReadResolvConf {
            path: path.as_ref().to_path_buf(),
            error: e,
        })?;

    resolv_conf::Config::parse(&data).map_err(|err| ResolverError::CouldNotParseResolvConf {
        path: path.as_ref().to_path_buf(),
        error: err,
    })
}
