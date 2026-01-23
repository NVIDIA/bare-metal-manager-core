pub mod files;
pub mod license;
pub mod packages;
pub mod staging;
pub mod types;

// Re-export commonly used types
// Re-export main functions
pub use files::copy_files;
pub use license::{extract_licenses, generate_attribution, write_attribution_file};
pub use packages::debian::package::install_packages;
pub use packages::debian::sources::{download_sources, download_sources_from_config};
pub use staging::assemble_staging_directory;
pub use types::{
    DISTROLESS_BASE_PACKAGES, License, PackageConfig, PackageInfo, SpdxDocument, SpdxPackage,
    is_base_package,
};
