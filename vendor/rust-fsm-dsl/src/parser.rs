use syn::{
    braced, bracketed, parenthesized,
    parse::{Error, Parse, ParseStream, Result},
    token::{Bracket, Paren},
    Ident, Token, Visibility,
};

mod kw {
    syn::custom_keyword!(derive);
}

/// The output of a state transition
pub struct Output(Option<Ident>);

impl Parse for Output {
    fn parse(input: ParseStream) -> Result<Self> {
        if input.lookahead1().peek(Bracket) {
            let output_content;
            bracketed!(output_content in input);
            Ok(Self(Some(output_content.parse()?)))
        } else {
            Ok(Self(None))
        }
    }
}

impl Into<Option<Ident>> for Output {
    fn into(self) -> Option<Ident> {
        self.0
    }
}

/// Represents a part of state transition without the initial state. The `Parse`
/// trait is implemented for the compact form.
pub struct TransitionEntry {
    pub input_value: Ident,
    pub final_state: Ident,
    pub output: Option<Ident>,
}

impl Parse for TransitionEntry {
    fn parse(input: ParseStream) -> Result<Self> {
        let input_value = input.parse()?;
        input.parse::<Token![=>]>()?;
        let final_state = input.parse()?;
        let output = input.parse::<Output>()?.into();
        Ok(Self {
            input_value,
            final_state,
            output,
        })
    }
}

/// Parses the transition in any of the possible formats.
pub struct TransitionDef {
    pub initial_state: Ident,
    pub transitions: Vec<TransitionEntry>,
}

impl Parse for TransitionDef {
    fn parse(input: ParseStream) -> Result<Self> {
        let initial_state = input.parse()?;
        // Parse the transition in the simple format
        // InitialState(Input) => ResultState [Output]
        let transitions = if input.lookahead1().peek(Paren) {
            let input_content;
            parenthesized!(input_content in input);
            let input_value = input_content.parse()?;
            input.parse::<Token![=>]>()?;
            let final_state = input.parse()?;
            let output = input.parse::<Output>()?.into();

            vec![TransitionEntry {
                input_value,
                final_state,
                output,
            }]
        } else {
            // Parse the transition in the compact format
            // InitialState => {
            //     Input1 => State1,
            //     Input2 => State2 [Output]
            // }
            input.parse::<Token![=>]>()?;
            let entries_content;
            braced!(entries_content in input);

            let entries: Vec<_> = entries_content
                .parse_terminated::<_, Token![,]>(TransitionEntry::parse)?
                .into_iter()
                .collect();
            if entries.is_empty() {
                return Err(Error::new_spanned(
                    initial_state,
                    "No transitions provided for a compact representation",
                ));
            }
            entries
        };
        Ok(Self {
            initial_state,
            transitions,
        })
    }
}

struct Derives {
    derives: Option<Vec<Ident>>,
}

impl Parse for Derives {
    fn parse(input: ParseStream) -> Result<Self> {
        let lookahead = input.lookahead1();
        if lookahead.peek(kw::derive) {
            let kw_derive = input.parse::<kw::derive>()?;
            let entries_content;
            parenthesized!(entries_content in input);
            let entries: Vec<_> = entries_content
                .parse_terminated::<_, Token![,]>(Ident::parse)?
                .into_iter()
                .collect();
            if entries.is_empty() {
                return Err(Error::new_spanned(kw_derive, "Derive list cannot be empty"));
            }
            return Ok(Derives {
                derives: Some(entries),
            });
        }
        Ok(Derives { derives: None })
    }
}

/// Parses the whole state machine definition in the following form (example):
///
/// ```rust,ignore
/// state_machine! {
///     CircuitBreaker(Closed)
///
///     Closed(Unsuccessful) => Open [SetupTimer],
///     Open(TimerTriggered) => HalfOpen,
///     HalfOpen => {
///         Successful => Closed,
///         Unsuccessful => Open [SetupTimer]
///     }
/// }
/// ```
pub struct StateMachineDef {
    /// The visibility modifier (applies to all generated items)
    pub visibility: Visibility,
    pub name: Ident,
    pub initial_state: Ident,
    pub transitions: Vec<TransitionDef>,
    pub derives: Option<Vec<Ident>>,
}

impl Parse for StateMachineDef {
    fn parse(input: ParseStream) -> Result<Self> {
        let Derives { derives } = input.parse()?;

        let visibility = input.parse()?;
        let name = input.parse()?;

        let initial_state_content;
        parenthesized!(initial_state_content in input);
        let initial_state = initial_state_content.parse()?;

        let transitions = input
            .parse_terminated::<_, Token![,]>(TransitionDef::parse)?
            .into_iter()
            .collect();

        Ok(Self {
            visibility,
            name,
            initial_state,
            transitions,
            derives,
        })
    }
}
