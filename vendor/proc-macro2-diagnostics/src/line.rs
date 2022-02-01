use std::fmt;
use std::borrow::Cow;

use crate::Level;

#[derive(Copy, Clone, PartialEq)]
enum Kind {
    New,
    Joined,
}

impl Kind {
    fn raw_split(self) -> (Cow<'static, str>, Cow<'static, str>) {
        match self {
            Kind::New => ("[".into(), "] ".into()),
            Kind::Joined => ("--- ".into(), ": ".into()),
        }
    }

    #[cfg(not(all(feature = "colors", not(nightly_diagnostics))))]
    fn split(self) -> (Cow<'static, str>, Cow<'static, str>) {
        self.raw_split()
    }

    #[cfg(all(feature = "colors", not(nightly_diagnostics)))]
    fn split(self) -> (Cow<'static, str>, Cow<'static, str>) {
        let style = yansi::Color::Blue.style().bold();
        let (prefix, suffix) = self.raw_split();
        let prefix = style.paint(prefix).to_string().into();
        let suffix = style.paint(suffix).to_string().into();
        (prefix, suffix)
    }
}

pub struct Line<'a> {
    pub level: Level,
    pub msg: &'a str,
    kind: Kind
}

impl<'a> Line<'a> {
    pub fn new(level: Level, msg: &'a str) -> Line<'a> {
        Line { kind: Kind::New, level, msg }
    }

    pub fn joined(level: Level, msg: &'a str) -> Line<'a> {
        Line { kind: Kind::Joined, level, msg }
    }

    pub fn is_new(&self) -> bool {
        self.kind == Kind::New
    }

    fn parse_kind(kind: Kind, string: &str) -> Option<Line<'_>> {
        let string = string.trim_start();
        let (prefix, suffix) = kind.split();
        if !string.starts_with(&*prefix) {
            return None;
        }

        let end = string.find(&*suffix)?;
        let level: Level = string[prefix.len()..end].parse().ok()?;
        let msg = &string[end + suffix.len()..];
        Some(Line { level, msg, kind })
    }

    pub fn parse(string: &str) -> Option<Line<'_>> {
        Line::parse_kind(Kind::Joined, string)
            .or_else(|| Line::parse_kind(Kind::New, string))
    }
}

impl fmt::Display for Line<'_> {
    #[cfg(all(feature = "colors", not(nightly_diagnostics)))]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        #[cfg(windows)]
        static INIT: std::sync::Once = std::sync::Once::new();

        #[cfg(windows)]
        INIT.call_once(|| {
            if cfg!(windows) && !Paint::enable_windows_ascii() {
                Paint::disable();
            }
        });

        use yansi::{Paint, Color};
        let style = match self.level {
            Level::Error => Color::Red.style().bold(),
            Level::Warning => Color::Yellow.style().bold(),
            Level::Note => Color::Green.style().bold(),
            Level::Help => Color::Cyan.style().bold(),
        };

        let ((prefix, suffix), msg) = (self.kind.split(), Paint::default(self.msg));
        write!(f, "{}{}{}{}", prefix, style.paint(self.level), suffix, msg)?;
        Color::Default.style().bold().fmt_prefix(f)?;
        Ok(())
    }

    #[cfg(not(all(feature = "colors", not(nightly_diagnostics))))]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (prefix, suffix) = self.kind.split();
        write!(f, "{}{}{}{}", prefix, self.level, suffix, self.msg)
    }
}
