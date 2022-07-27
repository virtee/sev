//! Modules for interfacing with the SEV firmware.
/// Modules containing FFI wrappers to C APIs
pub(crate) mod linux;
/// Rust-friendly APIs which use those FFI wrappers.
pub mod uapi;