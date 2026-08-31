//! Burrow: metadata-only, read-only shared-directory access.
//! This reference implementation exposes a safe directory API and `fork` copy;
//! OS-specific filesystem mounts can consume the same API without changing the protocol.

use crate::files::{safe_relative_path, FileError};
use serde::{Deserialize, Serialize};
use std::{
    fs, io,
    path::{Path, PathBuf},
};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum EntryKind {
    File,
    Directory,
    Symlink,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Entry {
    pub name: String,
    pub kind: EntryKind,
    pub size: u64,
}

#[derive(Clone, Debug)]
pub struct ReadOnlyShare {
    root: PathBuf,
}

impl ReadOnlyShare {
    pub fn open(root: impl AsRef<Path>) -> Result<Self, FileError> {
        let root = root.as_ref().canonicalize()?;
        if !root.is_dir() {
            return Err(FileError::Io(io::Error::new(
                io::ErrorKind::InvalidInput,
                "share root is not a directory",
            )));
        }
        Ok(Self { root })
    }

    pub fn list(&self, relative: impl AsRef<Path>) -> Result<Vec<Entry>, FileError> {
        let path = safe_relative_path(&self.root, relative)?;
        let mut out = Vec::new();
        for item in fs::read_dir(path)? {
            let item = item?;
            let meta = fs::symlink_metadata(item.path())?;
            let kind = if meta.file_type().is_symlink() {
                EntryKind::Symlink
            } else if meta.is_dir() {
                EntryKind::Directory
            } else {
                EntryKind::File
            };
            out.push(Entry {
                name: item.file_name().to_string_lossy().into_owned(),
                kind,
                size: meta.len(),
            });
        }
        out.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(out)
    }

    pub fn read(&self, relative: impl AsRef<Path>) -> Result<Vec<u8>, FileError> {
        let path = safe_relative_path(&self.root, relative)?;
        let meta = fs::symlink_metadata(&path)?;
        if meta.file_type().is_symlink() || !meta.is_file() {
            return Err(FileError::Io(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "only regular files are readable",
            )));
        }
        Ok(fs::read(path)?)
    }

    /// Explicit full-copy operation; this is the Burrow `fork` primitive.
    pub fn fork(
        &self,
        relative: impl AsRef<Path>,
        destination: impl AsRef<Path>,
    ) -> Result<(), FileError> {
        let source = safe_relative_path(&self.root, relative)?;
        let meta = fs::symlink_metadata(&source)?;
        if meta.file_type().is_symlink() {
            return Err(FileError::Io(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "symlinks cannot be forked",
            )));
        }
        let destination = destination.as_ref();
        if meta.is_file() {
            if let Some(parent) = destination.parent() {
                fs::create_dir_all(parent)?;
            }
            fs::copy(source, destination)?;
            return Ok(());
        }
        if meta.is_dir() {
            copy_dir(&source, destination)?;
            return Ok(());
        }
        Err(FileError::Io(io::Error::new(
            io::ErrorKind::InvalidInput,
            "unsupported file type",
        )))
    }
}

fn copy_dir(src: &Path, dst: &Path) -> Result<(), FileError> {
    fs::create_dir_all(dst)?;
    for entry in fs::read_dir(src)? {
        let entry = entry?;
        let meta = fs::symlink_metadata(entry.path())?;
        let target = dst.join(entry.file_name());
        if meta.is_dir() {
            copy_dir(&entry.path(), &target)?;
        } else if meta.is_file() {
            fs::copy(entry.path(), target)?;
        } else {
            return Err(FileError::Io(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "unsupported entry in fork",
            )));
        }
    }
    Ok(())
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum BurrowRequest {
    List { path: String },
    Read { path: String },
    Fork { path: String },
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum BurrowResponse {
    Listing(Vec<Entry>),
    Content(Vec<u8>),
    ForkAccepted,
    Error(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn read_only_share_lists_without_writing() {
        let d = tempfile::tempdir().unwrap();
        std::fs::write(d.path().join("a.txt"), b"hello").unwrap();
        let share = ReadOnlyShare::open(d.path()).unwrap();
        let entries = share.list(".").unwrap();
        assert_eq!(entries[0].name, "a.txt");
        assert_eq!(share.read("a.txt").unwrap(), b"hello");
    }
}
