use crate::cmd::args::{Cli, Commands, OutputFormat, RegistryAction};
use mlxconfig_registry::registries;
use mlxconfig_variables::{
    ConstraintValidationResult, DeviceInfo, MlxConfigVariable, MlxVariableRegistry,
    MlxVariableSpec, RegistryTargetConstraints,
};
use prettytable::{Cell, Row, Table};
use regex::Regex;
use serde_json;
use std::fs;

pub fn run_cli(cli: Cli) -> Result<(), Box<dyn std::error::Error>> {
    match cli.command {
        Some(Commands::Version) => {
            cmd_version();
        }
        Some(Commands::Registry { action }) => match action {
            RegistryAction::Generate {
                input_file,
                out_file,
            } => {
                cmd_registry_generate(input_file, out_file)?;
            }
            RegistryAction::Validate { yaml_file } => {
                cmd_registry_validate(yaml_file)?;
            }
            RegistryAction::List => {
                cmd_registry_list();
            }
            RegistryAction::Show {
                registry_name,
                output,
            } => {
                cmd_registry_show(&registry_name, output)?;
            }
            RegistryAction::Check {
                registry_name,
                device_type,
                part_number,
                fw_version,
            } => {
                cmd_registry_check(&registry_name, device_type, part_number, fw_version)?;
            }
        },
        None => {
            cmd_show_default_info();
        }
    }
    Ok(())
}

fn cmd_version() {
    println!("mlxconfig_embedded version 0.0.1");
    println!("Built with embedded mlxconfig_registry definitions at compile time");
}

fn cmd_registry_generate(
    input_file: std::path::PathBuf,
    out_file: Option<std::path::PathBuf>,
) -> Result<(), Box<dyn std::error::Error>> {
    let content = fs::read_to_string(&input_file).map_err(|e| {
        format!(
            "Failed to read input file '{}': {}",
            input_file.display(),
            e
        )
    })?;

    let registry = parse_mlx_show_confs(&content);
    let yaml = registry_to_yaml(&registry);

    match out_file {
        Some(path) => {
            fs::write(&path, &yaml)
                .map_err(|e| format!("Failed to write output file '{}': {}", path.display(), e))?;
            println!("Generated registry YAML: {}", path.display());
        }
        None => {
            print!("{yaml}");
        }
    }

    Ok(())
}

fn cmd_registry_validate(yaml_file: std::path::PathBuf) -> Result<(), Box<dyn std::error::Error>> {
    let content = fs::read_to_string(&yaml_file)
        .map_err(|e| format!("Failed to read YAML file '{}': {}", yaml_file.display(), e))?;

    match serde_yaml::from_str::<MlxVariableRegistry>(&content) {
        Ok(registry) => {
            println!("YAML file is valid!");
            println!("Registry: '{}'", registry.name);
            println!("Variables: {}", registry.variables.len());
            if registry.constraints.has_constraints() {
                println!("Constraints: {}", registry.constraint_summary());
            } else {
                println!("No constraints (compatible with all hardware)");
            }
        }
        Err(e) => {
            return Err(format!("Invalid YAML: {e}").into());
        }
    }

    Ok(())
}

fn cmd_registry_list() {
    let mut table = Table::new();

    // Set up table headers
    table.add_row(Row::new(vec![
        Cell::new("Name"),
        Cell::new("Variables"),
        Cell::new("Constraints"),
    ]));

    for registry in registries::get_all() {
        let constraints_display = if registry.constraints.has_constraints() {
            // Format constraints as pretty JSON.
            match serde_json::to_string_pretty(&registry.constraints) {
                Ok(json) => json,
                Err(_) => registry.constraint_summary(), // Fallback to human summary if JSON fails.
            }
        } else {
            "none".to_string()
        };

        table.add_row(Row::new(vec![
            Cell::new(&registry.name),
            Cell::new(&registry.variables.len().to_string()),
            Cell::new(&constraints_display),
        ]));
    }

    table.printstd();
}

fn cmd_registry_show(
    registry_name: &str,
    output_format: OutputFormat,
) -> Result<(), Box<dyn std::error::Error>> {
    let registry = registries::get(registry_name).ok_or_else(|| {
        format!(
            "Registry '{registry_name}' not found. Use 'registry list' to see available registries.",
        )
    })?;

    match output_format {
        OutputFormat::Table => show_registry_table(registry),
        OutputFormat::Json => show_registry_json(registry)?,
        OutputFormat::Yaml => show_registry_yaml(registry)?,
    }

    Ok(())
}

fn cmd_registry_check(
    registry_name: &str,
    device_type: Option<String>,
    part_number: Option<String>,
    fw_version: Option<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    let registry = registries::get(registry_name).ok_or_else(|| {
        format!(
            "Registry '{registry_name}' not found. Use 'registry list' to see available registries.",
        )
    })?;

    let mut device_info = DeviceInfo::new();
    if let Some(dt) = device_type {
        device_info = device_info.with_device_type(dt);
    }
    if let Some(pn) = part_number {
        device_info = device_info.with_part_number(pn);
    }
    if let Some(fw) = fw_version {
        device_info = device_info.with_fw_version(fw);
    }

    println!("Compatibility Check");
    println!("======================");
    println!("Registry: '{}'", registry.name);
    println!();
    println!("Device Information:");
    println!(
        "  Device type: {}",
        device_info
            .device_type
            .as_deref()
            .unwrap_or("(not specified)")
    );
    println!(
        "  Part number: {}",
        device_info
            .part_number
            .as_deref()
            .unwrap_or("(not specified)")
    );
    println!(
        "  FW version: {}",
        device_info
            .fw_version
            .as_deref()
            .unwrap_or("(not specified)")
    );
    println!();
    println!("Registry Constraints: {}", registry.constraint_summary());
    println!();

    let result = registry.validate_compatibility(&device_info);

    match result {
        ConstraintValidationResult::Valid => {
            println!("COMPATIBLE");
            println!("This device is compatible with the registry!");
        }
        ConstraintValidationResult::Unconstrained => {
            println!("UNCONSTRAINED");
            println!("Registry has no constraints - compatible with any device");
        }
        ConstraintValidationResult::Invalid { reasons } => {
            println!("INCOMPATIBLE");
            println!("This device is not compatible with the registry.");
            println!();
            println!("Reasons:");
            for reason in reasons {
                println!("  • {reason}");
            }
        }
    }

    Ok(())
}

fn cmd_show_default_info() {
    println!("Mellanox Hardware Configuration Registry");
    println!("=====================================");
    let total_variables: usize = registries::get_all()
        .iter()
        .map(|r| r.variables.len())
        .sum();

    let constrained_registries = registries::get_all()
        .iter()
        .filter(|r| r.constraints.has_constraints())
        .count();

    println!("Summary:");
    println!("  • Total registries: {}", registries::get_all().len());
    println!("  • Total variables: {total_variables}");
    println!("  • Constrained registries: {constrained_registries}");
    println!(
        "  • Universal registries: {}",
        registries::get_all().len() - constrained_registries
    );
    println!();
    println!("💡 Use --help to see available commands");
    println!("   Use 'registry list' to see all available registries");
    println!("   Use 'registry show <name>' to see registry details");
}

// Helper functions moved from main.rs
pub fn parse_mlx_show_confs(content: &str) -> MlxVariableRegistry {
    let mut variables = Vec::new();

    // More flexible regex patterns to match the MLX configuration format
    let section_re = Regex::new(r"^\s*([A-Z][A-Z0-9 _]+):$").unwrap();
    let var_re = Regex::new(r"^\s+([A-Z][A-Z0-9_]+)=<([^>]+)>\s*(.*)$").unwrap();

    let lines: Vec<&str> = content.lines().collect();
    let mut i = 0;

    while i < lines.len() {
        let line = lines[i];

        // Skip header lines
        if line.starts_with("List of configurations") || line.trim().is_empty() {
            i += 1;
            continue;
        }

        // Check for section header (we track this for potential future use)
        if let Some(_caps) = section_re.captures(line) {
            i += 1;
            continue;
        }

        // Check for variable definition
        if let Some(caps) = var_re.captures(line) {
            let var_name = caps[1].to_string();
            let var_type_str = &caps[2];
            let mut description = caps[3].to_string();

            // Look ahead for continuation lines (additional description)
            let mut j = i + 1;
            while j < lines.len() {
                let next_line = lines[j];
                // If next line starts with whitespace and doesn't match variable pattern, it's continuation
                if next_line.starts_with(' ')
                    && !var_re.is_match(lines[j])
                    && !section_re.is_match(lines[j])
                    && !next_line.trim().is_empty()
                {
                    description.push(' ');
                    description.push_str(next_line.trim());
                    j += 1;
                } else {
                    break;
                }
            }

            // Clean up description - remove extra whitespace and truncate if too long
            description = description.split_whitespace().collect::<Vec<_>>().join(" ");

            // More aggressive cleaning for problematic characters
            description = clean_description(&description);

            if description.len() > 120 {
                description.truncate(117);
                description.push_str("...");
            }

            let spec = parse_variable_type(var_type_str);

            variables.push(MlxConfigVariable {
                name: var_name,
                description,
                read_only: false, // MLX configs are generally writable
                spec,
            });

            i = j;
        } else {
            i += 1;
        }
    }

    MlxVariableRegistry {
        name: "MLX Hardware Configuration Registry".to_string(),
        variables,
        constraints: RegistryTargetConstraints::default(), // No constraints by default
    }
}

fn clean_description(desc: &str) -> String {
    // Just clean up whitespace - the escaping function will handle quotes
    desc.split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .trim()
        .to_string()
}

fn parse_variable_type(type_str: &str) -> MlxVariableSpec {
    // Handle specific patterns
    if type_str == "False|True" {
        return MlxVariableSpec::Enum {
            options: vec!["False".to_string(), "True".to_string()],
        };
    }

    if type_str == "NUM" {
        return MlxVariableSpec::Integer;
    }

    if type_str == "BYTES" {
        return MlxVariableSpec::Bytes;
    }

    if type_str == "BINARY" {
        return MlxVariableSpec::Binary;
    }

    // Check if it contains pipe-separated options (enum)
    if type_str.contains('|') {
        let options: Vec<String> = type_str.split('|').map(|s| s.trim().to_string()).collect();
        return MlxVariableSpec::Enum { options };
    }

    // Default to String for anything else
    MlxVariableSpec::String
}

pub fn registry_to_yaml(registry: &MlxVariableRegistry) -> String {
    let mut yaml = String::new();

    yaml.push_str(&format!(
        "name: \"{}\"\n",
        escape_yaml_string(&registry.name)
    ));

    // Add constraints section if any exist
    if registry.constraints.has_constraints() {
        yaml.push_str("constraints:\n");

        if let Some(device_types) = &registry.constraints.device_types {
            yaml.push_str("  device_types:\n");
            for device_type in device_types {
                yaml.push_str(&format!("    - \"{}\"\n", escape_yaml_string(device_type)));
            }
        }

        if let Some(part_numbers) = &registry.constraints.part_numbers {
            yaml.push_str("  part_numbers:\n");
            for part_number in part_numbers {
                yaml.push_str(&format!("    - \"{}\"\n", escape_yaml_string(part_number)));
            }
        }

        if let Some(fw_versions) = &registry.constraints.fw_versions {
            yaml.push_str("  fw_versions:\n");
            for fw_version in fw_versions {
                yaml.push_str(&format!("    - \"{}\"\n", escape_yaml_string(fw_version)));
            }
        }
    }

    yaml.push_str("variables:\n");

    for var in &registry.variables {
        yaml.push_str(&format!(
            "  - name: \"{}\"\n",
            escape_yaml_string(&var.name)
        ));
        yaml.push_str(&format!(
            "    description: \"{}\"\n",
            escape_yaml_string(&var.description)
        ));
        yaml.push_str(&format!("    read_only: {}\n", var.read_only));
        yaml.push_str("    spec:\n");

        match &var.spec {
            MlxVariableSpec::Boolean => {
                yaml.push_str("      type: \"Boolean\"\n");
            }
            MlxVariableSpec::Integer => {
                yaml.push_str("      type: \"Integer\"\n");
            }
            MlxVariableSpec::String => {
                yaml.push_str("      type: \"String\"\n");
            }
            MlxVariableSpec::Binary => {
                yaml.push_str("      type: \"Binary\"\n");
            }
            MlxVariableSpec::Bytes => {
                yaml.push_str("      type: \"Bytes\"\n");
            }
            MlxVariableSpec::Array => {
                yaml.push_str("      type: \"Array\"\n");
            }
            MlxVariableSpec::Enum { options } => {
                yaml.push_str("      type: \"Enum\"\n");
                yaml.push_str("      config:\n");
                yaml.push_str("        options: [");
                for (i, option) in options.iter().enumerate() {
                    if i > 0 {
                        yaml.push_str(", ");
                    }
                    yaml.push_str(&format!("\"{}\"", escape_yaml_string(option)));
                }
                yaml.push_str("]\n");
            }
            MlxVariableSpec::Preset { max_preset } => {
                yaml.push_str("      type: \"Preset\"\n");
                yaml.push_str("      config:\n");
                yaml.push_str(&format!("        max_preset: {max_preset}\n"));
            }
            MlxVariableSpec::BooleanArray { size } => {
                yaml.push_str("      type: \"BooleanArray\"\n");
                yaml.push_str("      config:\n");
                yaml.push_str(&format!("        size: {size}\n"));
            }
            MlxVariableSpec::IntegerArray { size } => {
                yaml.push_str("      type: \"IntegerArray\"\n");
                yaml.push_str("      config:\n");
                yaml.push_str(&format!("        size: {size}\n"));
            }
            MlxVariableSpec::EnumArray { options, size } => {
                yaml.push_str("      type: \"EnumArray\"\n");
                yaml.push_str("      config:\n");
                yaml.push_str("        options: [");
                for (i, option) in options.iter().enumerate() {
                    if i > 0 {
                        yaml.push_str(", ");
                    }
                    yaml.push_str(&format!("\"{}\"", escape_yaml_string(option)));
                }
                yaml.push_str("]\n");
                yaml.push_str(&format!("        size: {size}\n"));
            }
            MlxVariableSpec::BinaryArray { size } => {
                yaml.push_str("      type: \"BinaryArray\"\n");
                yaml.push_str("      config:\n");
                yaml.push_str(&format!("        size: {size}\n"));
            }
            MlxVariableSpec::Opaque => {
                yaml.push_str("      type: \"Opaque\"\n");
            }
        }
        yaml.push('\n');
    }

    yaml
}

fn escape_yaml_string(s: &str) -> String {
    // For YAML double-quoted strings, we only need to escape double quotes and backslashes
    s.replace("\\", "\\\\") // Escape backslashes first
        .replace("\"", "\\\"") // Escape double quotes
}

fn format_spec(spec: &MlxVariableSpec) -> String {
    match spec {
        MlxVariableSpec::Boolean => "boolean".to_string(),
        MlxVariableSpec::Integer => "integer".to_string(),
        MlxVariableSpec::String => "string".to_string(),
        MlxVariableSpec::Binary => "binary".to_string(),
        MlxVariableSpec::Bytes => "bytes".to_string(),
        MlxVariableSpec::Array => "array".to_string(),
        MlxVariableSpec::Enum { options } => {
            format!("enum [{}]", options.join(", "))
        }
        MlxVariableSpec::Preset { max_preset } => {
            format!("preset (max: {max_preset})")
        }
        MlxVariableSpec::BooleanArray { size } => {
            format!("boolean_array[{size}]")
        }
        MlxVariableSpec::IntegerArray { size } => {
            format!("integer_array[{size}]")
        }
        MlxVariableSpec::EnumArray { options, size } => {
            format!("enum_array[{size}] [{}]", options.join(", "))
        }
        MlxVariableSpec::BinaryArray { size } => {
            format!("binary_array[{size}]")
        }
        MlxVariableSpec::Opaque => "opaque".to_string(),
    }
}

fn show_registry_table(registry: &MlxVariableRegistry) {
    let mut table = Table::new();

    // Registry name row (spans all 4 columns)
    table.add_row(Row::new(vec![
        Cell::new("Registry Name"),
        Cell::new(&registry.name).with_hspan(3), // Span across 3 columns
    ]));

    // Variables count row (spans all 4 columns)
    table.add_row(Row::new(vec![
        Cell::new("Variables"),
        Cell::new(&registry.variables.len().to_string()).with_hspan(3),
    ]));

    // Constraints row (spans all 4 columns)
    let constraints_display = if registry.constraints.has_constraints() {
        match serde_json::to_string_pretty(&registry.constraints) {
            Ok(json) => json,
            Err(_) => registry.constraint_summary(),
        }
    } else {
        "none".to_string()
    };

    table.add_row(Row::new(vec![
        Cell::new("Constraints"),
        Cell::new(&constraints_display).with_hspan(3),
    ]));

    // Variables header row
    table.add_row(Row::new(vec![
        Cell::new("Variable Name").style_spec("Fb"),
        Cell::new("Read-Write").style_spec("Fb"),
        Cell::new("Type").style_spec("Fb"),
        Cell::new("Description").style_spec("Fb"),
    ]));

    // Add all variables
    for variable in &registry.variables {
        let read_write = if variable.read_only { "RO" } else { "RW" };
        let var_type = format_spec(&variable.spec);

        // Wrap description at 60 characters.
        let wrapped_description = wrap_text(&variable.description, 60);

        table.add_row(Row::new(vec![
            Cell::new(&variable.name),
            Cell::new(read_write),
            Cell::new(&var_type),
            Cell::new(&wrapped_description),
        ]));
    }

    table.printstd();
}

fn show_registry_json(registry: &MlxVariableRegistry) -> Result<(), Box<dyn std::error::Error>> {
    let json = serde_json::to_string_pretty(registry)
        .map_err(|e| format!("Failed to serialize registry to JSON: {e}"))?;
    println!("{json}");
    Ok(())
}

fn show_registry_yaml(registry: &MlxVariableRegistry) -> Result<(), Box<dyn std::error::Error>> {
    let yaml = serde_yaml::to_string(registry)
        .map_err(|e| format!("Failed to serialize registry to YAML: {e}"))?;
    print!("{yaml}");
    Ok(())
}

// Basic helper function to wrap text at specified width.
fn wrap_text(text: &str, width: usize) -> String {
    if text.len() <= width {
        return text.to_string();
    }

    let mut result = String::new();
    let mut current_line = String::new();

    for word in text.split_whitespace() {
        if current_line.len() + word.len() + 1 > width {
            if !result.is_empty() {
                result.push('\n');
            }
            result.push_str(&current_line);
            current_line = word.to_string();
        } else {
            if !current_line.is_empty() {
                current_line.push(' ');
            }
            current_line.push_str(word);
        }
    }

    if !current_line.is_empty() {
        if !result.is_empty() {
            result.push('\n');
        }
        result.push_str(&current_line);
    }

    result
}
