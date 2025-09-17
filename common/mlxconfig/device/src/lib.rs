// cmd module contains command-line interface logic and command handlers.
pub mod cmd;
// discovery module handles device discovery and enumeration using mlxfwmanager.
pub mod discovery;
// filters module provides filtering capabilities for device queries.
pub mod filters;
// info module defines the core device information structures.
pub mod info;
// proto module contains code for translating to/from protobuf
pub mod proto;
// report module contains the MlxDeviceReport and helpers.
pub mod report;
