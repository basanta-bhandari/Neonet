pub mod app;
pub mod bootstrap;
pub mod burrow;
pub mod core;
pub mod files;
pub mod identity;
pub mod installer;
pub mod lobby;
pub mod messaging;
pub mod node;
pub mod pair;
pub mod protocol;
pub mod shell;
pub mod ssh;
pub mod storage;
pub mod transport;
pub mod update;

pub const SOFTWARE_VERSION: &str = env!("CARGO_PKG_VERSION");
