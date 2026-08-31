//! Installer metadata and platform-service guidance. The actual installer is
//! shipped as scripts in `installer/`; this module keeps generated service
//! configuration explicit rather than hiding OS-specific branches in Rust.

pub const SERVICE_NAME: &str = "neonet";
pub const SUPPORTED_PLATFORMS: &[&str] = &["linux", "macos", "windows"];
