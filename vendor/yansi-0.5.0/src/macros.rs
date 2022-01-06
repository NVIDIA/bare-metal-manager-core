macro_rules! style_builder_for {
    ($T:ty, |$s:ident| $props:expr, $($name:ident: $property:ident),*) => ($(
    docify!([
        Enables the @[_$name]_ style on @code{self}.

        @fence @rust
        use yansi::Paint; @nl @nl

        @{"println!(\"Using "} @[$name] @{": {}\", "}
            @{r#"Paint::new("hi")"#} @[.$name] @{"());"}
        @fence
    ];
        #[inline]
        pub fn $name(self) -> $T {
            let mut $s = self;
            $props.set(Property::$property);
            $s
        }
    );)*)
}
