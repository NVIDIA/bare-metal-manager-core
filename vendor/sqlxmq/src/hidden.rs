use crate::{CurrentJob, JobBuilder, JobRegistry};

#[doc(hidden)]
pub struct BuildFn(pub for<'a> fn(&'a mut JobBuilder<'static>) -> &'a mut JobBuilder<'static>);
#[doc(hidden)]
pub struct RunFn(pub fn(&JobRegistry, CurrentJob));
