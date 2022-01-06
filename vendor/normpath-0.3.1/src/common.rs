use std::io;
use std::path::Path;

use super::BasePathBuf;

#[inline(always)]
pub(super) fn is_base(_: &Path) -> bool {
    true
}

#[inline(always)]
pub(super) fn to_base(_: &Path) -> io::Result<BasePathBuf> {
    unreachable!();
}

pub(super) fn normalize(path: &Path) -> io::Result<BasePathBuf> {
    // This method rejects null bytes and empty paths, which is consistent with
    // [GetFullPathNameW] on Windows.
    path.canonicalize().and_then(BasePathBuf::new)
}

pub(super) fn push(base: &mut BasePathBuf, path: &Path) {
    if !path.as_os_str().is_empty() {
        base.replace_with(|mut base| {
            base.push(path);
            base
        });
    }
}
