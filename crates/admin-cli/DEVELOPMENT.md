# Admin CLI Development Guide

This guide covers how to develop new subcommands, and work on existing
subcommands, in the `admin-cli` crate (for `carbide-admin-cli`).

## Table of Contents

- [Module Structure](#module-structure)
- [The Dispatch Trait](#the-dispatch-trait)
- [RuntimeContext and RuntimeConfig](#runtimecontext-and-runtimeconfig)
- [Creating a New Subcommand](#creating-a-new-subcommand)
- [Testing](#testing)

## Module Structure

Each subcommand lives in its own module directory under `src/`. A complete
subcommand module should generally contain, at least, these four basic files:

```
src/
└── my_subcommand/
    ├── mod.rs      # Module root with Dispatch implementation.
    ├── args.rs     # Clap argument definitions.
    ├── cmds.rs     # Command handler implementations.
    └── tests.rs    # Unit tests.
```

### mod.rs

The module root file declares submodules, exports the `Cmd` type, and
implements the `Dispatch` trait. This is where command routing happens.

An example `mod.rs` might look something like:
```rust
pub mod args;
pub mod cmds;

#[cfg(test)]
mod tests;

use ::rpc::admin_cli::CarbideCliResult;
pub use args::Cmd;

use crate::cfg::dispatch::Dispatch;
use crate::cfg::runtime::RuntimeContext;

impl Dispatch for Cmd {
    async fn dispatch(self, ctx: RuntimeContext) -> CarbideCliResult<()> {
        match self {
            Cmd::Show(args) => {
                cmds::show(args, ctx.config.format, &ctx.api_client).await
            }
            Cmd::Create(args) => {
                cmds::create(args, &ctx.api_client).await
            }
        }
    }
}
```

### args.rs

Contains all clap argument definitions. The root `Cmd` enum defines
available subcommands, with each variant holding its argument struct.

```rust
use clap::Parser;

#[derive(Parser, Debug)]
pub enum Cmd {
    #[clap(about = "Display items")]
    Show(ShowArgs),

    #[clap(about = "Create a new item")]
    Create(CreateArgs),
}

#[derive(Parser, Debug)]
pub struct ShowArgs {
    #[clap(help = "Item ID to display")]
    pub id: Option<String>,

    #[clap(short, long, help = "Filter by name")]
    pub name: Option<String>,
}

#[derive(Parser, Debug)]
pub struct CreateArgs {
    #[clap(long, help = "Name for the new item")]
    pub name: String,

    #[clap(long, help = "Optional description")]
    pub description: Option<String>,
}
```

### cmds.rs

Contains the actual command handler implementations. Each handler receives
parsed arguments and runtime dependencies (API client, format, etc.), which
are passed down via the main `RuntimeContext` through the `Dispatch` handler.

```rust
use ::rpc::admin_cli::{CarbideCliResult, OutputFormat};

use super::args::{CreateArgs, ShowArgs};
use crate::rpc::ApiClient;

pub async fn show(
    args: ShowArgs,
    format: OutputFormat,
    api_client: &ApiClient,
) -> CarbideCliResult<()> {
    // Implementation here
    Ok(())
}

pub async fn create(
    args: CreateArgs,
    api_client: &ApiClient,
) -> CarbideCliResult<()> {
    // Implementation here
    Ok(())
}
```

## The Dispatch Trait

The `Dispatch` trait (defined in `src/cfg/dispatch.rs`) provides a unified
interface for executing commands with the runtime context:

```rust
pub(crate) trait Dispatch {
    fn dispatch(
        self,
        ctx: RuntimeContext,
    ) -> impl std::future::Future<Output = CarbideCliResult<()>>;
}
```

Every subcommand's `Cmd` type must implement this trait. The implementation
routes to the appropriate handler in `cmds.rs` based on which variant was
parsed.

### Key Points

- The trait consumes `self` (takes ownership of the parsed command).
- Returns a `CarbideCliResult<()>` future.
- The `ctx` parameter provides all runtime dependencies.

### Handling Output Files

Depending on runtime output configuration, a command may write to a file. If your
command  needs the output file, take `mut ctx` to get mutable access:

```rust
impl Dispatch for Cmd {
    async fn dispatch(self, mut ctx: RuntimeContext) -> CarbideCliResult<()> {
        match self {
            Cmd::Show(args) => {
                cmds::show(
                    args,
                    &mut ctx.output_file,  // <-- Do it here.
                    ctx.config.format,
                    &ctx.api_client,
                ).await
            }
        }
    }
}
```

## RuntimeContext and RuntimeConfig

The `RuntimeContext` (defined in `src/cfg/runtime.rs`) bundles all runtime
dependencies passed to dispatch handlers:

```rust
pub struct RuntimeContext {
    pub api_client: ApiClient,
    pub config: RuntimeConfig,
    pub output_file: Pin<Box<dyn tokio::io::AsyncWrite>>,
}

pub struct RuntimeConfig {
    pub format: OutputFormat,           // Output format (Table, JSON, CSV)
    pub page_size: usize,               // Pagination size for list operations
    pub extended: bool,                 // Show extended/detailed output
    pub cloud_unsafe_op_enabled: bool,  // Allow unsafe cloud operations
    pub sort_by: SortField,             // Sort field for list operations
}
```

### Using RuntimeConfig Fields

Extract only what your handler needs:

```rust
// Simple handler -- just needs format and API client.
cmds::show(args, ctx.config.format, &ctx.api_client).await

// Paginated list additionally needs page_size.
cmds::list(args, ctx.config.format, &ctx.api_client, ctx.config.page_size).await

// Extended output additionally needs the extended flag.
cmds::show(args, ctx.config.format, &ctx.api_client, ctx.config.extended).await

// For those needing support for sorting.
cmds::list(args, &ctx.api_client, ctx.config.sort_by).await

// ..and finally, writing to file.
cmds::export(&mut ctx.output_file, args, &ctx.api_client).await
```

## Creating a New Subcommand

### Step 1: Create the Module Directory

```bash
mkdir src/my_subcommand
```

### Step 2: Create args.rs

Define your command enum and argument structs:

```rust
/*
 * SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES.
 * SPDX-License-Identifier: Apache-2.0
 * ..etc etc.
 */

use clap::Parser;

#[derive(Parser, Debug)]
pub enum Cmd {
    #[clap(about = "Show items")]
    Show(ShowArgs),
}

#[derive(Parser, Debug)]
pub struct ShowArgs {
    #[clap(help = "Optional item ID")]
    pub id: Option<String>,
}
```

### Step 3: Create cmds.rs

Implement your command handlers:

```rust
/*
 * SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES.
 * SPDX-License-Identifier: Apache-2.0
 * ..etc etc.
 */

use ::rpc::admin_cli::{CarbideCliResult, OutputFormat};

use super::args::ShowArgs;
use crate::rpc::ApiClient;

pub async fn show(
    args: ShowArgs,
    format: OutputFormat,
    api_client: &ApiClient,
) -> CarbideCliResult<()> {
    // Your implementation here.
    Ok(())
}
```

### Step 4: Create mod.rs

Wire up the dispatch:

```rust
/*
 * SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES.
 * SPDX-License-Identifier: Apache-2.0
 * ..etc etc.
 */

pub mod args;
pub mod cmds;

#[cfg(test)]
mod tests;

use ::rpc::admin_cli::CarbideCliResult;
pub use args::Cmd;

use crate::cfg::dispatch::Dispatch;
use crate::cfg::runtime::RuntimeContext;

impl Dispatch for Cmd {
    async fn dispatch(self, ctx: RuntimeContext) -> CarbideCliResult<()> {
        match self {
            Cmd::Show(args) => {
                cmds::show(args, ctx.config.format, &ctx.api_client).await
            }
        }
    }
}
```

### Step 5: Create tests.rs

Add unit tests (see [Testing](#testing) section below).

### Step 6: Register the Subcommand

Add to `src/main.rs`:

```rust
mod my_subcommand;
```

Add to `CliCommand` enum in `src/cfg/cli_options.rs`:

```rust
pub enum CliCommand {
    // ... existing commands ...
    #[clap(about = "My subcommand description", subcommand)]
    MySubcommand(my_subcommand::Cmd),
}
```

Add dispatch routing in `src/main.rs`:

```rust
match command {
    // ... existing commands ...
    CliCommand::MySubcommand(cmd) => cmd.dispatch(ctx).await?,
}
```

## Testing

Each subcommand should have a `tests.rs` file that validates command
structure and argument parsing. Tests are organized into categories.
Note the repetitive/boilerplate comments. While not needed, it helps those
who happen to look at your specific `tests.rs`.

### Test File Structure

```rust
/*
 * SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES.
 * SPDX-License-Identifier: Apache-2.0
 * ..etc etc.
 */

// The intent of the tests.rs file is to test the integrity of the
// command, including things like basic structure parsing, enum
// translations, and any external input validators that are
// configured. Specific "categories" are:
//
// Command Structure - Baseline debug_assert() of the entire command.
// Argument Parsing  - Ensure required/optional arg combinations parse correctly.
// ValueEnum Parsing - Test clap ValueEnum translations (if applicable).
// Validation Logic  - Test business logic validators (if applicable).

use clap::{CommandFactory, Parser};

use super::args::*;
```

### Boilerplate Tests (Required!)

Every subcommand MUST have a basic command structure test:

```rust
// verify_cmd_structure runs a baseline clap debug_assert()
// to do basic command configuration checking and validation,
// ensuring things like unique argument definitions, group
// configurations, argument references, etc. Things that would
// otherwise be missed until runtime.
#[test]
fn verify_cmd_structure() {
    Cmd::command().debug_assert();
}
```

From there, you should also have a test that it parses with
no arguments (or minimal arguments).

```rust
// parse_show_no_args ensures show parses with no
// arguments (all items).
#[test]
fn parse_show_no_args() {
    let cmd = Cmd::try_parse_from(["my-cmd", "show"])
        .expect("should parse show");

    match cmd {
        Cmd::Show(args) => {
            assert!(args.id.is_none());
        }
        _ => panic!("expected Show variant"),
    }
}
```

### Conditional Tests (Optional, based on command features)

You should add these additional types of tests based on what
your command supports.

#### Commands with Required Arguments

For required arguments, you should test that these parse as expected,
with the added benefit of it being a nice, self-documenting way for
people to see how to interact with your command.

```rust
// parse_create_missing_required_fails ensures create
// fails without required arguments.
#[test]
fn parse_create_missing_required_fails() {
    let result = Cmd::try_parse_from(["my-cmd", "create"]);
    assert!(result.is_err(), "should fail without --name");
}
```

#### Commands with Optional Filters

Similar to required arguments, test that various --flag arguments
parse as expected, again being a self-documenting way to show
how to interact (and not interact) with your command.

```rust
// parse_show_with_name ensures show parses with --name.
#[test]
fn parse_show_with_name() {
    let cmd = Cmd::try_parse_from(["my-cmd", "show", "--name", "test"])
        .expect("should parse show with name");

    match cmd {
        Cmd::Show(args) => {
            assert_eq!(args.name, Some("test".to_string()));
        }
        _ => panic!("expected Show variant"),
    }
}
```

#### Commands with ValueEnum Arguments

When testing enums that don't derive `PartialEq`, use `matches!`:

```rust
// parse_create_with_type ensures create parses with
// --type argument.
#[test]
fn parse_create_with_type() {
    let cmd = Cmd::try_parse_from([
        "my-cmd", "create", "--type", "dpu"
    ]).expect("should parse create with type");

    match cmd {
        Cmd::Create(args) => {
            assert!(matches!(args.item_type, ItemType::Dpu));
        }
        _ => panic!("expected Create variant"),
    }
}

// parse_create_invalid_type_fails ensures create fails
// with invalid type value.
#[test]
fn parse_create_invalid_type_fails() {
    let result = Cmd::try_parse_from([
        "my-cmd", "create", "--type", "invalid"
    ]);
    assert!(result.is_err(), "should fail with invalid type");
}
```

#### Commands with Argument Groups

Test mutually exclusive or required-together arguments:

```rust
// parse_show_conflict_fails ensures show fails with
// conflicting arguments.
#[test]
fn parse_show_conflict_fails() {
    let result = Cmd::try_parse_from([
        "my-cmd", "show", "--id", "123", "--all"
    ]);
    assert!(result.is_err(), "should fail with both --id and --all");
}

// parse_update_requires_both ensures update requires
// both username and password together.
#[test]
fn parse_update_requires_both() {
    let result = Cmd::try_parse_from([
        "my-cmd", "update", "--username", "admin"
    ]);
    assert!(result.is_err(), "should fail with username but no password");
}
```

#### Commands with Custom Validators

Test business logic validation methods:

```rust
// validate_no_duplicates ensures validate() passes
// with unique values.
#[test]
fn validate_no_duplicates() {
    let cmd = Cmd::try_parse_from([
        "my-cmd", "create", "--item", "a", "--item", "b"
    ]).expect("should parse");

    match cmd {
        Cmd::Create(args) => {
            assert!(args.validate().is_ok(), "unique items should validate");
        }
        _ => panic!("expected Create variant"),
    }
}

// validate_duplicates_fail ensures validate() fails
// with duplicate values.
#[test]
fn validate_duplicates_fail() {
    let cmd = Cmd::try_parse_from([
        "my-cmd", "create", "--item", "a", "--item", "a"
    ]).expect("should parse");

    match cmd {
        Cmd::Create(args) => {
            assert!(args.validate().is_err(), "duplicates should fail");
        }
        _ => panic!("expected Create variant"),
    }
}
```

### Test ID Constants

For commands that take IDs, define constants at the top of the test file:

```rust
// Standard UUID format for VpcId, InstanceId, etc.
const TEST_VPC_ID: &str = "00000000-0000-0000-0000-000000000001";

// Known format for MachineId.
const TEST_MACHINE_ID: &str =
    "fm100ht038bg3qsho433vkg684heguv282qaggmrsh2ugn1qk096n2c6hcg";
```

### Comment Style

Test function comments should include the name of the test,
as well as what the test is testing.

```rust
// parse_show_with_filters ensures show parses with
// multiple filter arguments.
#[test]
fn parse_show_with_filters() {
    // ...
}
```

### Running Tests

Nothing exciting here, but worth mentioning for completeness!

```bash
# Run all tests
cargo test

# Run tests for a specific subcommand
cargo test my_subcommand::tests

# Run a specific test
cargo test my_subcommand::tests::verify_cmd_structure
```
