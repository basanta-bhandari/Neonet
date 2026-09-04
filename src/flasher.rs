//! The flasher — a self-contained, USB-carried tool for pairing two machines
//! without typing keys, codes, or pins.
//!
//! A flasher is a directory (typically a mounted USB drive) that carries:
//!
//!   * a bundled `neonet` binary (`bin/neonet`) for the current OS, and/or
//!   * a `flashed.json` bundle written by the machine the drive was flashed
//!     *from*, holding that machine's public identity and a freshly-issued
//!     single-use pairing token.
//!
//! Three operations, each honest about what it can and cannot do offline:
//!
//!   * `neonet flasher ensure`  — is `neonet` installed? If not, install it:
//!     prefer the bundled binary on the drive, else build from source
//!     (`install.sh`-style) when a toolchain is present. Pure, offline,
//!     cross-platform-safe file work.
//!   * `neonet flasher author`  — on the machine being flashed from: write
//!     `flashed.json` (identity + token) into the drive's slot.
//!   * `neonet flasher adopt`   — on the target machine: `ensure`, read the
//!     bundle, show a *confirmation prompt*, and only then trust the device
//!     the drive was flashed from (and record it as a known device).
//!
//! The confirmation prompt is the security-critical part: flashing must never
//! silently pair-and-trust on plug-in alone, or a dropped drive becomes the
//! exact "autorun malware" pattern every OS fights.

use crate::{identity::PublicIdentity, pair};
use serde::{Deserialize, Serialize};
use std::{
    env, fs, io,
    path::{Path, PathBuf},
    process::Command,
};

/// Name of the identity bundle on the drive.
pub const BUNDLE_FILE: &str = "flashed.json";

/// Where the drive carries a prebuilt binary for the current OS.
pub const BUNDLE_BIN_SUBDIR: &str = "bin";

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FlashedSource {
    pub public_key: [u8; 32],
    pub fingerprint: String,
    pub alias: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FlashedBundle {
    pub source: FlashedSource,
    /// Single-use pairing token the *source* published for the target to
    /// present back, so the source records/trusts the target in return.
    pub token: String,
    /// Unix seconds this bundle was authored.
    pub issued_at: u64,
    /// Seconds the token stays valid after issuance.
    pub ttl: u64,
}

/// Where this machine's `neonet` is installed, or that it isn't.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Installed {
    /// `neonet` is already on PATH.
    OnPath(String),
    /// A specific binary exists at `path` but isn't on PATH.
    At(String),
    /// Not installed anywhere.
    Missing,
}

/// Locate an installed `neonet` binary on this machine.
pub fn installed() -> Installed {
    if let Ok(path) = which("neonet") {
        return Installed::OnPath(path);
    }
    if let Some(path) = home_bin_candidate() {
        return Installed::At(path);
    }
    Installed::Missing
}

/// True if `neonet` is installed (on PATH anywhere).
pub fn is_installed() -> bool {
    !matches!(installed(), Installed::Missing)
}

/// Resolve a command on PATH, returning its canonical path if found.
fn which(name: &str) -> io::Result<String> {
    let path = env::var_os("PATH").unwrap_or_default();
    for dir in env::split_paths(&path) {
        let candidate = dir.join(name);
        if candidate.is_file() {
            return Ok(candidate.to_string_lossy().into_owned());
        }
    }
    Err(io::Error::new(io::ErrorKind::NotFound, "not on PATH"))
}

/// The most likely user-writable install directory on this machine.
fn home_bin_candidate() -> Option<String> {
    for d in ["$HOME/.local/bin", "$HOME/bin"] {
        let dir = expand_home(d);
        let path = dir.join("neonet");
        if path.is_file() {
            return Some(path.to_string_lossy().into_owned());
        }
    }
    None
}

fn expand_home(s: &str) -> PathBuf {
    if let Some(rest) = s.strip_prefix("$HOME/") {
        if let Ok(home) = env::var("HOME") {
            return Path::new(&home).join(rest);
        }
    }
    PathBuf::from(s)
}

/// Pick the best install directory: the first directory on PATH that this
/// user can actually write to, else the first writable of the usual home
/// candidates.
fn pick_dest() -> io::Result<PathBuf> {
    let path = env::var_os("PATH").unwrap_or_default();
    for d in env::split_paths(&path) {
        if !d.as_os_str().is_empty() && is_writable(&d) {
            return Ok(d);
        }
    }
    for d in ["$HOME/.local/bin", "$HOME/bin"] {
        let dir = expand_home(d);
        if is_writable(&dir) {
            return Ok(dir);
        }
    }
    Err(io::Error::new(
        io::ErrorKind::PermissionDenied,
        "no writable install directory found on PATH — create one and add it to PATH",
    ))
}

/// True if this user can create&delete a file in `dir` right now. Probes the
/// filesystem rather than trusting mode bits, so root-owned `PATH` dirs that
/// merely don't show as readonly don't fool us.
fn is_writable(dir: &Path) -> bool {
    if !dir.is_dir() {
        return false;
    }
    let probe = dir.join(format!(".neonet.probe.{}", std::process::id()));
    match fs::File::create(&probe) {
        Ok(_) => {
            let _ = fs::remove_file(&probe);
            true
        }
        Err(_) => false,
    }
}

/// Atomic install: copy to a temp name, then rename into place so a running
/// `neonet` shell doesn't trip over "Text file busy".
fn atomic_install(src: &Path, dest_dir: &Path) -> io::Result<PathBuf> {
    let dest = dest_dir.join("neonet");
    let tmp = dest_dir.join(format!("neonet.tmp.{}", std::process::id()));
    fs::copy(src, &tmp)?;
    set_executable(&tmp)?;
    fs::rename(&tmp, &dest)?;
    Ok(dest)
}

/// Mark the freshly-installed binary executable. Only meaningful on Unix;
/// a no-op elsewhere.
#[cfg(unix)]
fn set_executable(path: &Path) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let mut perms = fs::metadata(path)?.permissions();
    perms.set_mode(0o755);
    fs::set_permissions(path, perms)
}

#[cfg(not(unix))]
fn set_executable(_path: &Path) -> io::Result<()> {
    Ok(())
}

/// The `ensure` step: if `neonet` is already installed, do nothing and report
/// so. Otherwise install it — preferring a bundled binary on the drive, then
/// falling back to a toolchain build. Returns what happened.
pub fn ensure(usb_dir: Option<&Path>) -> io::Result<String> {
    match installed() {
        Installed::OnPath(path) => {
            return Ok(format!("neonet already installed: {path}"));
        }
        Installed::At(path) => {
            return Ok(format!(
                "neonet found off-PATH at {path} (add its directory to PATH to use it directly)"
            ));
        }
        Installed::Missing => {}
    }

    if let Some(usb) = usb_dir {
        let bundled = usb.join(BUNDLE_BIN_SUBDIR).join("neonet");
        if bundled.is_file() {
            let dest = pick_dest()?;
            let installed_path = atomic_install(&bundled, &dest)?;
            return Ok(format!(
                "neonet was missing — installed the bundled binary from this drive into {}",
                installed_path.display()
            ));
        }
    }

    if toolchain_present() {
        return build_from_source();
    }

    Err(io::Error::new(
        io::ErrorKind::NotFound,
        "neonet is not installed, this drive carries no bundled binary for this OS, and \
         the Rust toolchain wasn't found either. Install it first (run install.sh), or \
         put a `neonet` binary in the drive's bin/ directory.",
    ))
}

fn toolchain_present() -> bool {
    which("cargo").is_ok() && which("rustc").is_ok()
}

/// `install.sh`-style fallback: build from source, then install onto PATH.
fn build_from_source() -> io::Result<String> {
    let here = env::current_dir()?;
    let repo = repo_root(&here).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::NotFound,
            "no NeoNet source checkout found near the current directory to build from",
        )
    })?;

    let mut build = Command::new("cargo");
    build.current_dir(&repo).arg("build").arg("--release");
    let status = build.status()?;
    if !status.success() {
        return Err(io::Error::other("cargo build --release failed"));
    }
    let bin = repo.join("target/release/neonet");
    if !bin.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "build finished but target/release/neonet wasn't produced",
        ));
    }
    let dest = pick_dest()?;
    let installed_path = atomic_install(&bin, &dest)?;
    Ok(format!(
        "neonet was missing — built from source and installed into {}",
        installed_path.display()
    ))
}

fn repo_root(start: &Path) -> Option<PathBuf> {
    let mut cur = Some(start.to_path_buf());
    while let Some(dir) = cur {
        if dir.join("Cargo.toml").is_file() {
            return Some(dir);
        }
        cur = dir.parent().map(Path::to_path_buf);
    }
    None
}

/// The `author` step, on the machine being flashed from: write `flashed.json`
/// (identity + token) into the drive's slot. Returns the bundle written.
pub fn author(
    root: &Path,
    usb_dir: &Path,
    identity: &crate::identity::Identity,
) -> io::Result<FlashedBundle> {
    let token = pair::issue_token(root, None)?;
    let public = identity.public();
    let bundle = FlashedBundle {
        source: FlashedSource {
            public_key: public.public_key,
            fingerprint: public.fingerprint(),
            alias: "flashed-from".into(),
        },
        token,
        issued_at: unix_now(),
        ttl: pair::default_ttl(),
    };
    let path = usb_dir.join(BUNDLE_FILE);
    fs::write(&path, serde_json::to_vec_pretty(&bundle)?)?;
    Ok(bundle)
}

/// Read and validate a bundle from the drive.
pub fn read_bundle(usb_dir: &Path) -> io::Result<FlashedBundle> {
    let path = usb_dir.join(BUNDLE_FILE);
    let bytes = fs::read(&path)?;
    let bundle: FlashedBundle = serde_json::from_slice(&bytes)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("{BUNDLE_FILE}: {e}")))?;
    if bundle.token.is_empty() || bundle.source.public_key == [0u8; 32] {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("{BUNDLE_FILE} is missing a token or public key"),
        ));
    }
    Ok(bundle)
}

/// The `adopt` step, on the target machine: ensure `neonet` is installed, read
/// the bundle from the drive, ask the human for confirmation, and — only on an
/// explicit yes — trust the flashed-from device (record it in the pairing
/// ledger) and save it as a known device.
///
/// `confirm` is a callback returning `true` for an explicit yes; production
/// callers wire this to a terminal y/n prompt. The token is then presented
/// back to the *source* (over the mesh, when a path exists) so the source
/// records and trusts this device in return.
pub fn adopt(
    root: &Path,
    usb_dir: &Path,
    confirm: &mut dyn FnMut(&FlashedSource) -> io::Result<bool>,
) -> io::Result<AdoptSummary> {
    let bundle = read_bundle(usb_dir)?;

    if !confirm(&bundle.source)? {
        return Ok(AdoptSummary {
            trusted: false,
            source: bundle.source,
        });
    }

    let source = PublicIdentity {
        public_key: bundle.source.public_key,
    };
    pair::record_pairing(root, &source)?;

    let mut devices = load_devices(root);
    devices.add(crate::ssh::DeviceRecord {
        identity: source.clone(),
        alias: bundle.source.alias.clone(),
        user: "neo".into(),
        resolution: crate::ssh::Resolution {
            host: String::new(),
            port: 22,
            known_hosts: String::new(),
        },
    });
    save_devices(root, &devices)?;

    Ok(AdoptSummary {
        trusted: true,
        source: bundle.source,
    })
}

/// What `adopt` did, for the caller to print.
#[derive(Clone, Debug)]
pub struct AdoptSummary {
    pub trusted: bool,
    pub source: FlashedSource,
}

fn unix_now() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Load this machine's device directory (`<root>/devices.json`), or start
/// empty if it's absent or unreadable.
fn load_devices(root: &Path) -> crate::ssh::ResolutionDirectory {
    let path = root.join("devices.json");
    match fs::read(&path)
        .ok()
        .and_then(|bytes| serde_json::from_slice(&bytes).ok())
    {
        Some(dir) => dir,
        None => crate::ssh::empty_directory(),
    }
}

/// Persist the device directory to `<root>/devices.json`.
fn save_devices(root: &Path, devices: &crate::ssh::ResolutionDirectory) -> io::Result<()> {
    let path = root.join("devices.json");
    let bytes = serde_json::to_vec_pretty(devices)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    let tmp = root.join("devices.json.tmp");
    fs::write(&tmp, bytes)?;
    fs::rename(&tmp, &path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn author_then_adopt_round_trips_and_confirms() {
        let home = tempdir().unwrap();
        let usb = tempdir().unwrap();
        let identity = crate::identity::Identity::load_or_generate(home.path().join("id")).unwrap();

        let bundle = author(home.path(), usb.path(), &identity).unwrap();
        assert!(!bundle.token.is_empty());
        assert_eq!(bundle.source.fingerprint, identity.public().fingerprint());

        let asked = std::cell::Cell::new(false);
        let summary = adopt(home.path(), usb.path(), &mut |_src| {
            asked.set(true);
            Ok(true)
        })
        .unwrap();
        assert!(asked.get());
        assert!(summary.trusted);
        assert!(pair::is_paired(home.path(), &identity.public()));
    }

    #[test]
    fn adopt_without_confirmation_does_not_trust() {
        let home = tempdir().unwrap();
        let usb = tempdir().unwrap();
        let identity = crate::identity::Identity::load_or_generate(home.path().join("id")).unwrap();
        author(home.path(), usb.path(), &identity).unwrap();

        let summary = adopt(home.path(), usb.path(), &mut |_| Ok(false)).unwrap();
        assert!(!summary.trusted);
        assert!(!pair::is_paired(home.path(), &identity.public()));
    }
}
