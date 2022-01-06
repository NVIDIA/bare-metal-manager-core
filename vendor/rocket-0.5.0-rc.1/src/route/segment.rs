use crate::http::RawStr;

#[derive(Debug, Clone)]
pub struct Segment {
    pub value: String,
    pub dynamic: bool,
    pub trailing: bool,
}

impl Segment {
    pub fn from(segment: &RawStr) -> Self {
        let mut value = segment;
        let mut dynamic = false;
        let mut trailing = false;

        if segment.starts_with('<') && segment.ends_with('>') {
            dynamic = true;
            value = &segment[1..(segment.len() - 1)];

            if value.ends_with("..") {
                trailing = true;
                value = &value[..(value.len() - 2)];
            }
        }

        Segment { value: value.to_string(), dynamic, trailing }
    }
}
