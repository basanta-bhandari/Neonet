//! SSH Redirector. NeoNet resolves an identity/alias to a real SSH endpoint;
//! OpenSSH remains responsible for the SSH protocol itself.

use crate::identity::PublicIdentity;
use serde::{Deserialize, Serialize};
use std::{
    io,
    net::IpAddr,
    process::{Command, ExitStatus},
};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Resolution {
    pub host: String,
    pub port: u16,
    pub known_hosts: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct DeviceRecord {
    pub identity: PublicIdentity,
    pub alias: String,
    pub user: String,
    pub resolution: Resolution,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ResolutionDirectory {
    devices: Vec<DeviceRecord>,
}

impl ResolutionDirectory {
    pub fn add(&mut self, record: DeviceRecord) {
        self.devices
            .retain(|d| d.identity != record.identity && d.alias != record.alias);
        self.devices.push(record);
    }
    pub fn resolve(&self, id_or_alias: &str) -> Option<&DeviceRecord> {
        self.devices
            .iter()
            .find(|d| d.alias == id_or_alias || d.identity.fingerprint() == id_or_alias)
    }
    pub fn list(&self) -> &[DeviceRecord] {
        &self.devices
    }
}

pub fn validate_host(host: &str) -> bool {
    if host.parse::<IpAddr>().is_ok() {
        return true;
    }
    !host.is_empty()
        && host.len() <= 253
        && host
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
}

pub fn connect(
    directory: &ResolutionDirectory,
    device_id: &str,
    command: &[String],
) -> io::Result<ExitStatus> {
    let record = directory
        .resolve(device_id)
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "device not found"))?;
    if !validate_host(&record.resolution.host) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid SSH host",
        ));
    }
    let target = format!("{}@{}", record.user, record.resolution.host);
    let mut ssh = Command::new("ssh");
    ssh.arg("-p")
        .arg(record.resolution.port.to_string())
        .arg("-o")
        .arg(format!(
            "UserKnownHostsFile={}",
            record.resolution.known_hosts
        ))
        .arg(&target);
    if !command.is_empty() {
        // Commands are passed verbatim to the remote shell, like `ssh host ls
        // -la`; no local expansion happens.
        ssh.arg("--").args(command);
    }
    ssh.status()
}

pub fn whoami(identity: &PublicIdentity) -> String {
    identity.fingerprint()
}

pub fn devices(directory: &ResolutionDirectory) -> Vec<(String, String)> {
    directory
        .list()
        .iter()
        .map(|d| (d.alias.clone(), d.identity.fingerprint()))
        .collect()
}

pub fn empty_directory() -> ResolutionDirectory {
    ResolutionDirectory {
        devices: Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn alias_resolves() {
        let id = PublicIdentity {
            public_key: [7; 32],
        };
        let mut d = empty_directory();
        d.add(DeviceRecord {
            identity: id.clone(),
            alias: "core".into(),
            user: "neo".into(),
            resolution: Resolution {
                host: "127.0.0.1".into(),
                port: 22,
                known_hosts: "known_hosts".into(),
            },
        });
        assert!(d.resolve("core").is_some());
        assert!(d.resolve(&id.fingerprint()).is_some());
    }
}
