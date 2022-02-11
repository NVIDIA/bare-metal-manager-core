use std::env;
use std::ffi::OsString;
use std::io;
use std::mem;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::ffi::OsStringExt;
use std::path::Component;
use std::path::Path;
use std::path::PathBuf;
use std::path::Prefix;
use std::path::PrefixComponent;
use std::ptr;

use winapi::shared::minwindef::DWORD;
use winapi::um::fileapi::GetFullPathNameW;

use super::BasePath;
use super::BasePathBuf;

macro_rules! static_assert {
    ( $condition:expr ) => {
        const _: () = [()][!$condition as usize];
    };
}

const SEPARATOR: u16 = b'\\' as _;

pub(super) fn is_base(path: &Path) -> bool {
    matches!(path.components().next(), Some(Component::Prefix(_)))
}

pub(super) fn to_base(path: &Path) -> io::Result<BasePathBuf> {
    let base = env::current_dir()?;
    debug_assert!(is_base(&base));

    let mut base = BasePathBuf(base.into_os_string());
    base.push(path);
    Ok(base)
}

fn convert_separators(path: &Path) -> (Vec<u16>, PathBuf) {
    let mut wide_path: Vec<_> = path.as_os_str().encode_wide().collect();
    for ch in &mut wide_path {
        if ch == &b'/'.into() {
            *ch = SEPARATOR;
        }
    }
    let path = OsString::from_wide(&wide_path).into();
    (wide_path, path)
}

fn normalize_verbatim(path: &Path) -> BasePathBuf {
    let mut path: Vec<_> = path.as_os_str().encode_wide().collect();
    // Normalizing more of a verbatim path can change its meaning. The part
    // changed here is required for the path to be verbatim.
    for ch in &mut path[..4] {
        if ch == &b'/'.into() {
            *ch = SEPARATOR;
        }
    }
    BasePathBuf(OsString::from_wide(&path))
}

pub(super) fn normalize_virtually(
    initial_path: &Path,
) -> io::Result<BasePathBuf> {
    // [GetFullPathNameW] always converts separators.
    let (mut wide_path, path) = convert_separators(initial_path);

    if wide_path.contains(&0) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "normpath: strings passed to WinAPI cannot contains NULs",
        ));
    }
    wide_path.push(0);

    match path.components().next() {
        // Verbatim paths should not be modified.
        Some(Component::Prefix(prefix)) if prefix.kind().is_verbatim() => {
            return Ok(normalize_verbatim(initial_path));
        }
        Some(Component::RootDir)
            if wide_path.len() >= 3 && wide_path[1] == SEPARATOR =>
        {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "normpath: partial UNC prefixes are invalid",
            ));
        }
        _ => {}
    }

    let mut buffer = Vec::new();
    let mut capacity = 0;
    loop {
        capacity = unsafe {
            GetFullPathNameW(
                wide_path.as_ptr(),
                capacity,
                buffer.as_mut_ptr(),
                ptr::null_mut(),
            )
        };
        if capacity == 0 {
            break Err(io::Error::last_os_error());
        }

        // This assertion should never fail.
        static_assert!(mem::size_of::<DWORD>() <= mem::size_of::<usize>());

        let length = capacity as usize;
        if let Some(mut additional_capacity) =
            length.checked_sub(buffer.capacity())
        {
            assert_ne!(0, additional_capacity);

            // WinAPI can recommend an insufficient capacity that causes it to
            // return incorrect results, so extra space is reserved as a
            // workaround.
            macro_rules! extra_capacity {
                () => {
                    2
                };
            }
            capacity =
                capacity.checked_add(extra_capacity!()).ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::Other,
                        "required path length is too large for WinAPI",
                    )
                })?;
            additional_capacity += extra_capacity!();

            buffer.reserve(additional_capacity);
            continue;
        }

        // SAFETY: These characters were initialized by the system call.
        unsafe {
            buffer.set_len(length);
        }
        break Ok(BasePathBuf(OsString::from_wide(&buffer)));
    }
}

pub(super) fn normalize(path: &Path) -> io::Result<BasePathBuf> {
    path.metadata().and_then(|_| normalize_virtually(path))
}

fn get_prefix(base: &BasePath) -> PrefixComponent<'_> {
    if let Some(Component::Prefix(prefix)) = base.components().next() {
        prefix
    } else {
        // Base paths should always have a prefix.
        panic!(
            "base path is missing a prefix: {}",
            base.as_path().display(),
        );
    }
}

fn push_separator(base: &mut BasePathBuf) {
    // https://github.com/rust-lang/rust/issues/89658
    /*
    base.replace_with(|mut base| {
        // Add a separator if necessary.
        base.push("");
        base
    });
    */

    const SEPARATOR: &str = "\\";

    if let Some(Component::Prefix(prefix)) = base.components().next_back() {
        if matches!(prefix.kind(), Prefix::Disk(_) | Prefix::VerbatimDisk(_)) {
            return;
        }
    }
    // This inefficient implementation must be used until the above issue is
    // resolved.
    if !base.0.to_string_lossy().ends_with(SEPARATOR) {
        base.0.push(SEPARATOR);
    }
}

pub(super) fn push(base: &mut BasePathBuf, initial_path: &Path) {
    // [GetFullPathNameW] always converts separators.
    let (wide_path, path) = convert_separators(initial_path);

    let mut components = path.components();
    let mut next_component = components.next();
    match next_component {
        Some(Component::Prefix(prefix)) => {
            // Verbatim paths should not be modified.
            if prefix.kind().is_verbatim() {
                *base = normalize_verbatim(initial_path);
                return;
            }

            next_component = components.next();
            // Other prefixes are absolute, except drive-relative prefixes.
            if !matches!(prefix.kind(), Prefix::Disk(_))
                || prefix.kind() != get_prefix(base).kind()
                // Equivalent to [path.has_root()] but more efficient.
                || next_component == Some(Component::RootDir)
            {
                *base = BasePathBuf(path.into_os_string());
                return;
            }
        }
        Some(Component::RootDir) => {
            let mut buffer = get_prefix(base).as_os_str().to_os_string();
            buffer.push(path);
            *base = BasePathBuf(buffer);
            return;
        }
        _ => {
            while let Some(component) = next_component {
                match component {
                    Component::CurDir => {}
                    Component::ParentDir if base.pop().is_ok() => {}
                    _ => break,
                }
                next_component = components.next();
            }
        }
    }

    if let Some(component) = next_component {
        push_separator(base);
        base.0.push(component);

        let components = components.as_path();
        if !components.as_os_str().is_empty() {
            push_separator(base);
            base.0.push(components);
        }
    }

    // At least one separator should be kept.
    if wide_path.last() == Some(&SEPARATOR)
        || wide_path.ends_with(&[SEPARATOR, b'.'.into()])
    {
        push_separator(base);
    }
}
