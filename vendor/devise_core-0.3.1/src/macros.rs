macro_rules! trait_method {
    ($name:ident: $kind:ty, $default:ident) => (
        fn $name(&mut self, value: $kind) -> Result<FnOutput> {
            $default(self, value)
        }
    )
}

macro_rules! trait_forward {
    (<$T:ident as $Trait:ident>::$name:ident: $kind:ty) => (
        fn $name(&mut self, value: $kind) -> Result<FnOutput> {
            <$T as $Trait>::$name(self, value)
        }
    )
}

macro_rules! function {
    ($kind:ty) => (Option<Box<dyn FnMut(&mut Self, $kind) -> Result<FnOutput>>>)
}

macro_rules! builder {
    ($name:ident: $kind:ty, $field:ident) => (
        pub fn $name<F>(mut self, mut f: F) -> Self
            where F: FnMut(&mut Self, $kind) -> FnOutput + 'static
        {
            self.$field = Some(Box::new(move |s, v| Ok(f(s, v))));
            self
        }
    )
}

macro_rules! try_builder {
    ($try_name:ident: $kind:ty, $field:ident) => (
        pub fn $try_name<F>(mut self, f: F) -> Self
            where F: FnMut(&mut Self, $kind) -> Result<FnOutput> + 'static
        {
            self.$field = Some(Box::new(f));
            self
        }
    )
}

macro_rules! builder_forward {
    ($name:ident : $kind:ty, $field:ident, $default:expr) => (
        fn $name(&mut self, value: $kind) -> Result<FnOutput> {
            match self.$field.take() {
                Some(mut f) => {
                    let result = f(self, value);
                    self.$field = Some(f);
                    result
                }
                None => $default(&mut *self, value)
            }
        }
    )
}

macro_rules! builder_def_fwd {
    ($name:ident : $kind:ty, $field:ident, $default:expr) => (
        fn $name(&mut self, value: $kind) -> Result<FnOutput> {
            if let Some(mut f) = self.$field.take() {
                let result = f(self, value);
                self.$field = Some(f);
                result?;
            }

            $default(&mut *self, value)
        }
    )
}
