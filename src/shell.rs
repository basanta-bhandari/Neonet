//! The NeoNet shell: a DOS-styled interactive terminal that boots on bare
//! `neonet` and puts every tool at the prompt. It is a pure tool surface for
//! v1 — no virtual drive, no mounted-remote-drive notion. State persists a
//! small `history` file under `NEONET_HOME/shell/`.
//!
//! The `Vfs` type below remains in place as a base so a later Burrow-backed
//! drive layer can be re-introduced without churn; the shell does not expose
//! filesystem commands in v1.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::io;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

pub const CYAN: &str = "\x1b[1;36m";
pub const GREEN: &str = "\x1b[1;32m";
pub const YELLOW: &str = "\x1b[1;33m";
pub const RED: &str = "\x1b[1;31m";
pub const DIM: &str = "\x1b[2m";
pub const BOLD: &str = "\x1b[1m";
pub const RESET: &str = "\x1b[0m";

pub const VERSION: &str = "0.1.0";

/// pydos-style bytes formatter (B/KB/…/TB).
pub fn fmt_bytes(mut b: u64) -> String {
    let units = ["B", "KB", "MB", "GB", "TB"];
    let mut i = 0;
    while b >= 1024 && i < units.len() - 1 {
        b /= 1024;
        i += 1;
    }
    format!("{b}{}", units[i])
}

pub fn now_hm() -> String {
    let since = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    // Local wall-clock without libc: prefer `date` when present, else UTC.
    if let Ok(out) = std::process::Command::new("date").arg("+%H:%M").output() {
        if out.status.success() {
            if let Ok(s) = String::from_utf8(out.stdout) {
                let s = s.trim().to_string();
                if s.len() == 5 {
                    return s;
                }
            }
        }
    }
    let h = (since / 3600) % 24;
    let m = (since / 60) % 60;
    format!("{h:02}:{m:02} UTC")
}

/// The pydos-style banner, re-skinned.
pub fn logo() -> &'static str {
    "
   ███╗   ██╗███████╗ ██████╗ ███╗   ██╗███████╗████████╗
   ████╗  ██║██╔════╝██╔═══██╗████╗  ██║██╔════╝╚══██╔══╝
   ██╔██╗ ██║█████╗  ██║   ██║██╔██╗ ██║█████╗     ██║
   ██║╚██╗██║██╔══╝  ██║   ██║██║╚██╗██║██╔══╝     ██║
   ██║ ╚████║███████╗╚██████╔╝██║ ╚████║███████╗   ██║
   ╚═╝  ╚═══╝╚══════╝ ╚═════╝ ╚═╝  ╚═══╝╚══════╝   ╚═╝
"
}

/// Boot splash: banner. (No drive to load any more — v1 is a pure tool shell.)
pub fn boot() {
    println!("{GREEN}{}{RESET}", logo());
    println!("\n{BOLD}NeoNet Shell{VERSION} {RESET}");
}

/// Home screen, mirroring pydos's `display_home`.
pub fn home(_mounted: Option<&str>) {
    println!("{GREEN}{}{RESET}", logo());
    println!("NEONET SHELL [Version {VERSION}]");
    println!("ENTER 'HELP' TO GET STARTED.");
    println!("Time: {}", now_hm());
}

// ── history ───────────────────────────────────────────────────────────────────

#[derive(Default, Serialize, Deserialize)]
pub struct History {
    pub entries: Vec<String>,
}

impl History {
    pub fn load(root: &Path) -> Self {
        match std::fs::read(root.join("shell").join("history")) {
            Ok(bytes) => serde_json::from_slice(&bytes).unwrap_or_default(),
            Err(_) => Self::default(),
        }
    }

    pub fn push(&mut self, line: &str) {
        let line = line.trim().to_string();
        if line.is_empty() {
            return;
        }
        if self.entries.last() != Some(&line) {
            self.entries.push(line);
        }
        if self.entries.len() > 50 {
            let excess = self.entries.len() - 50;
            self.entries.drain(..excess);
        }
    }

    pub fn save(&self, root: &Path) -> io::Result<()> {
        let dir = root.join("shell");
        std::fs::create_dir_all(&dir)?;
        let bytes = serde_json::to_vec(self).map_err(io::Error::other)?;
        let path = dir.join("history");
        let tmp = path.with_extension("tmp");
        std::fs::write(&tmp, bytes)?;
        std::fs::rename(tmp, path)
    }
}

// ── tokenizer ─────────────────────────────────────────────────────────────────

/// Split a command line into words, honoring single and double quotes.
pub fn tokenize(line: &str) -> Vec<String> {
    let mut words = Vec::new();
    let mut current = String::new();
    let mut quote: Option<char> = None;
    for c in line.chars() {
        match quote {
            Some(q) => {
                if c == q {
                    quote = None;
                } else {
                    current.push(c);
                }
            }
            None => match c {
                '\'' | '"' => {
                    if current.is_empty() {
                        quote = Some(c);
                    } else {
                        current.push(c);
                    }
                }
                c if c.is_whitespace() => {
                    if !current.is_empty() {
                        words.push(std::mem::take(&mut current));
                    }
                }
                c => current.push(c),
            },
        }
    }
    if !current.is_empty() {
        words.push(current);
    }
    words
}

// ── virtual drive ─────────────────────────────────────────────────────────────

#[derive(Serialize, Deserialize)]
pub struct File {
    pub content: String,
}

#[derive(Serialize, Deserialize)]
pub enum Node {
    Dir(Dir),
    File(File),
}

#[derive(Serialize, Deserialize)]
pub struct Dir {
    pub children: BTreeMap<String, Node>,
}

impl Dir {
    fn empty() -> Self {
        Self {
            children: BTreeMap::new(),
        }
    }
    fn items(&self) -> Vec<(String, &Node)> {
        self.children.iter().map(|(n, x)| (n.clone(), x)).collect()
    }
}

impl Default for Vfs {
    fn default() -> Self {
        Self::new()
    }
}

/// The persistent virtual drive. Paths are POSIX-style with `/` root.
pub struct Vfs {
    root: Dir,
    cwd: Vec<String>,
}

impl Vfs {
    pub fn new() -> Self {
        let mut root = Dir::empty();
        for name in ["bin", "usr", "tmp", "home", "Apps"] {
            let mut dir = Dir::empty();
            if name == "Apps" {
                dir.children
                    .insert("Utilities".into(), Node::Dir(Dir::empty()));
                dir.children.insert("Games".into(), Node::Dir(Dir::empty()));
            }
            root.children.insert(name.into(), Node::Dir(dir));
        }
        Self {
            root,
            cwd: Vec::new(),
        }
    }

    pub fn load(root: &Path) -> Self {
        match std::fs::read(root.join("shell").join("vfs.json")) {
            Ok(bytes) => match serde_json::from_slice::<Dir>(&bytes) {
                Ok(root_dir) => Self {
                    root: root_dir,
                    cwd: Vec::new(),
                },
                Err(_) => Self::new(),
            },
            Err(_) => Self::new(),
        }
    }

    pub fn save(&self, root: &Path) -> io::Result<()> {
        let dir = root.join("shell");
        std::fs::create_dir_all(&dir)?;
        let bytes = serde_json::to_vec(&self.root).map_err(io::Error::other)?;
        let path = dir.join("vfs.json");
        let tmp = path.with_extension("tmp");
        std::fs::write(&tmp, bytes)?;
        std::fs::rename(tmp, path)
    }

    pub fn cwd_string(&self) -> String {
        if self.cwd.is_empty() {
            "/".to_string()
        } else {
            format!("/{}", self.cwd.join("/"))
        }
    }

    fn node_at(&self, parts: &[String]) -> Option<&Node> {
        let mut node = self.root.children.get(parts.first()?)?;
        for part in &parts[1..] {
            match node {
                Node::Dir(dir) => node = dir.children.get(part)?,
                Node::File(_) => return None,
            }
        }
        Some(node)
    }

    fn node_at_mut(&mut self, parts: &[String]) -> Option<&mut Node> {
        let mut node = self.root.children.get_mut(parts.first()?)?;
        for part in &parts[1..] {
            match node {
                Node::Dir(dir) => node = dir.children.get_mut(part)?,
                Node::File(_) => return None,
            }
        }
        Some(node)
    }

    fn dir_for<'a>(&'a self, parent: &[String]) -> Option<&'a Dir> {
        if parent.is_empty() {
            Some(&self.root)
        } else {
            match self.node_at(parent) {
                Some(Node::Dir(dir)) => Some(dir),
                _ => None,
            }
        }
    }

    fn dir_for_mut(&mut self, parent: &[String]) -> Option<&mut Dir> {
        if parent.is_empty() {
            Some(&mut self.root)
        } else {
            match self.node_at_mut(parent) {
                Some(Node::Dir(dir)) => Some(dir),
                _ => None,
            }
        }
    }

    /// Resolve `path` (relative to cwd) into split parts; `..` pops, `.` is no-op.
    fn split_path(&self, path: &str) -> Vec<String> {
        let base = if path.starts_with('/') {
            Vec::new()
        } else {
            self.cwd.clone()
        };
        let mut parts = base;
        for piece in path.split('/') {
            match piece {
                "" | "." => {}
                ".." => {
                    parts.pop();
                }
                name => parts.push(name.to_string()),
            }
        }
        parts
    }

    /// The parts of the target's parent (or the cwd for `/`), and the target name.
    fn parent_and_name(&self, path: &str) -> Result<(Vec<String>, String), String> {
        let parts = self.split_path(path);
        let (parent, name) = parts.split_at(parts.len().saturating_sub(1));
        if name.is_empty() {
            return Err("malformed path".into());
        }
        Ok((parent.to_vec(), name[0].clone()))
    }

    pub fn cd(&mut self, path: &str) -> Result<(), String> {
        let parts = self.split_path(path);
        if parts.is_empty() {
            self.cwd.clear();
            return Ok(());
        }
        match self.node_at(&parts) {
            Some(Node::Dir(_)) => {
                self.cwd = parts;
                Ok(())
            }
            Some(Node::File(_)) => Err(format!("is not a directory: {path}")),
            None => Err(format!("no such directory: {path}")),
        }
    }

    pub fn ls(&self) -> Vec<(String, &Node)> {
        if self.cwd.is_empty() {
            self.root.items()
        } else {
            match self.node_at(&self.cwd) {
                Some(Node::Dir(dir)) => dir.items(),
                _ => Vec::new(),
            }
        }
    }

    pub fn mkdir(&mut self, path: &str) -> Result<(), String> {
        let (parent, name) = self.parent_and_name(path)?;
        let dir = self
            .dir_for(&parent)
            .ok_or_else(|| format!("no such directory to hold {path}"))?;
        if dir.children.contains_key(&name) {
            return Err(format!("already exists: {name}"));
        }
        self.dir_for_mut(&parent)
            .unwrap()
            .children
            .insert(name, Node::Dir(Dir::empty()));
        Ok(())
    }

    pub fn rmdir(&mut self, path: &str) -> Result<(), String> {
        let (parent, name) = self.parent_and_name(path)?;
        let dir = self
            .dir_for(&parent)
            .ok_or_else(|| format!("not found: {name}"))?;
        match dir.children.get(&name) {
            Some(Node::Dir(sub)) => {
                if !sub.children.is_empty() {
                    return Err(format!("directory not empty: {name}"));
                }
            }
            Some(Node::File(_)) => return Err(format!("not a directory: {name}")),
            None => return Err(format!("not found: {name}")),
        }
        self.dir_for_mut(&parent).unwrap().children.remove(&name);
        Ok(())
    }

    pub fn rm(&mut self, path: &str) -> Result<(), String> {
        let (parent, name) = self.parent_and_name(path)?;
        let dir = self
            .dir_for(&parent)
            .ok_or_else(|| format!("not found: {name}"))?;
        if matches!(dir.children.get(&name), Some(Node::Dir(sub)) if !sub.children.is_empty()) {
            return Err(format!("directory not empty: {name}"));
        }
        if !dir.children.contains_key(&name) {
            return Err(format!("not found: {name}"));
        }
        self.dir_for_mut(&parent).unwrap().children.remove(&name);
        Ok(())
    }

    pub fn touch(&mut self, path: &str) -> Result<(), String> {
        let (parent, name) = self.parent_and_name(path)?;
        let has_parent = self.dir_for(&parent).is_some();
        if !has_parent {
            return Err(format!("no such directory to hold {path}"));
        }
        self.dir_for_mut(&parent)
            .unwrap()
            .children
            .entry(name)
            .or_insert_with(|| {
                Node::File(File {
                    content: String::new(),
                })
            });
        Ok(())
    }

    pub fn cat(&self, path: &str) -> Result<String, String> {
        let parts = self.split_path(path);
        match self.node_at(&parts) {
            Some(Node::File(file)) => Ok(file.content.clone()),
            Some(Node::Dir(_)) => Err("is a directory, use 'ls'".into()),
            None => Err(format!("not found: {path}")),
        }
    }

    /// Append `text` (with a newline) to a file.
    pub fn write(&mut self, path: &str, text: &str) -> Result<(), String> {
        self.touch(path)?;
        let parts = self.split_path(path);
        let Node::File(file) = self.node_at_mut(&parts).unwrap() else {
            unreachable!()
        };
        if !file.content.is_empty() && !file.content.ends_with('\n') {
            file.content.push('\n');
        }
        file.content.push_str(text);
        file.content.push('\n');
        Ok(())
    }

    pub fn copy(&mut self, src: &str, dst: &str) -> Result<(), String> {
        let content = self.cat(src)?;
        self.write(dst, &content)
    }

    pub fn move_(&mut self, src: &str, dst: &str) -> Result<(), String> {
        let content = self.cat(src)?;
        self.write(dst, &content)?;
        self.rm(src)?;
        Ok(())
    }

    pub fn rename(&mut self, old: &str, new: &str) -> Result<(), String> {
        let content = self.cat(old)?;
        let (parent, old_name) = self.parent_and_name(old)?;
        let (dparent, new_name) = self.parent_and_name(new)?;
        if parent != dparent {
            return Err("rename stays in the same directory (use copy/move)".to_string());
        }
        let dir = self
            .dir_for_mut(&parent)
            .ok_or_else(|| "not found".to_string())?;
        if dir.children.contains_key(&old_name) {
            dir.children.remove(&old_name);
            dir.children.insert(new_name, Node::File(File { content }));
            Ok(())
        } else {
            Err("not found".into())
        }
    }

    /// Lines of `needle` matches: (file name, matching line).
    pub fn grep(&self, needle: &str) -> Vec<(String, String)> {
        let mut hits = Vec::new();
        for (name, node) in self.ls() {
            if let Node::File(file) = node {
                for line in file.content.lines() {
                    if line.contains(needle) {
                        hits.push((name.clone(), line.to_string()));
                    }
                }
            }
        }
        hits
    }
}

// ── prompt ────────────────────────────────────────────────────────────────────

pub enum Context {
    Local,
    Remote(String),
}

pub fn prompt(clock: bool, context: &Context, cwd: &str) -> String {
    let time = if clock {
        format!("{} {}", DIM, now_hm())
    } else {
        String::new()
    };
    match context {
        Context::Local => format!("NEONET {GREEN}L:{cwd}{RESET}>{time} "),
        Context::Remote(alias) => {
            format!("NEONET[{YELLOW}{alias}{RESET}] {GREEN}{cwd}{RESET}>{time} ")
        }
    }
}

// ── host system info (sysinfo) ────────────────────────────────────────────────

/// Best-effort host rows for `sysinfo`: OS/distro name, kernel, arch, hostname,
/// RAM total, and a battery line when present.
pub fn system_info() -> Vec<String> {
    let mut rows = Vec::new();
    rows.push(format!("Host        {}", hostname()));
    rows.push(format!("OS          {}", distro_name()));
    rows.push(format!("Kernel      {}", kernel()));
    rows.push(format!("RAM total   {}", ram_total()));
    if let Some(battery) = battery() {
        rows.push(battery);
    }
    rows
}

fn hostname() -> String {
    ["/etc/hostname", "/proc/sys/kernel/hostname", "hostname"]
        .iter()
        .find_map(|path| std::fs::read_to_string(path).ok())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "unknown".into())
}

fn distro_name() -> String {
    if let Ok(text) = std::fs::read_to_string("/etc/os-release") {
        for line in text.lines() {
            if let Some(rest) = line.strip_prefix("NAME=") {
                return rest.trim_matches('"').trim().to_string();
            }
        }
    }
    if std::path::Path::new("/etc/arch-release").exists() {
        return "Arch Linux".into();
    }
    if std::path::Path::new("/etc/debian_version").exists() {
        return "Debian".into();
    }
    std::env::consts::OS.to_string()
}

fn kernel() -> String {
    std::process::Command::new("uname")
        .arg("-sr")
        .output()
        .ok()
        .filter(|o| o.status.success())
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| std::env::consts::OS.to_string())
}

fn ram_total() -> String {
    let kb = std::fs::read_to_string("/proc/meminfo")
        .ok()
        .and_then(|text| {
            text.lines().find_map(|line| {
                line.strip_prefix("MemTotal:").map(|v| {
                    v.trim()
                        .trim_end_matches("kB")
                        .trim()
                        .parse::<u64>()
                        .unwrap_or(0)
                })
            })
        })
        .unwrap_or(0);
    fmt_bytes(kb * 1024)
}

fn battery() -> Option<String> {
    let base = std::path::Path::new("/sys/class/power_supply");
    let entry = std::fs::read_dir(base)
        .ok()?
        .filter_map(|e| e.ok())
        .find(|e| {
            let name = e.file_name().to_string_lossy().into_owned();
            name.starts_with("BAT") && name != "BATTERY"
        })?;
    let name = entry.file_name().to_string_lossy().into_owned();
    let capacity = std::fs::read_to_string(base.join(&name).join("capacity"))
        .ok()
        .map(|s| s.trim().to_string());
    let charging = std::fs::read_to_string(base.join(&name).join("status"))
        .ok()
        .map(|s| s.trim().to_string());
    match (capacity, charging) {
        (Some(cap), status) => {
            let status = status.unwrap_or_else(|| "?".into());
            let tag = if status == "Charging" {
                "charging"
            } else {
                "on battery"
            };
            Some(format!("Battery     {cap}% ({tag})"))
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tokenize_respects_quotes() {
        assert_eq!(tokenize("send thing \"two words\" 'three words'"), {
            let mut v = vec!["send".to_string(), "thing".to_string()];
            v.push("two words".into());
            v.push("three words".into());
            v
        });
        assert_eq!(
            tokenize("  a   b  "),
            vec!["a".to_string(), "b".to_string()]
        );
    }

    #[test]
    fn fresh_drive_has_standard_layout_and_persists() {
        let home = tempfile::tempdir().unwrap();
        let mut vfs = Vfs::new();
        assert!(vfs.ls().iter().any(|(n, _)| n == "bin"));
        vfs.mkdir("home/newdir").unwrap();
        vfs.touch("home/a.txt").unwrap();
        vfs.write("home/a.txt", "hello world").unwrap();
        vfs.cd("home/newdir").unwrap();
        assert_eq!(vfs.cwd_string(), "/home/newdir");
        vfs.save(home.path()).unwrap();

        let mut loaded = Vfs::load(home.path());
        loaded.cd("/home/newdir").ok();
        assert_eq!(loaded.cwd_string(), "/home/newdir");
        assert_eq!(loaded.cat("/home/a.txt").unwrap(), "hello world\n");
    }

    #[test]
    fn directory_ops_behave_like_dos() {
        let mut vfs = Vfs::new();
        vfs.mkdir("/work").unwrap();
        assert!(vfs.mkdir("/work").is_err());
        assert!(vfs.rmdir("/work").is_ok());
        // rmdir of a directory with content fails
        vfs.mkdir("/work").unwrap();
        vfs.touch("/work/keep.txt").unwrap();
        assert!(vfs.rmdir("/work").is_err());
        assert!(vfs.rm("/work/keep.txt").is_ok());
        assert!(vfs.rmdir("/work").is_ok());
        // .. navigation
        vfs.mkdir("/tmp/sub").unwrap();
        vfs.cd("/tmp/sub").ok();
        assert_eq!(vfs.cwd_string(), "/tmp/sub");
        vfs.cd("..").ok();
        assert_eq!(vfs.cwd_string(), "/tmp");
        vfs.cd("/").ok();
        assert_eq!(vfs.cwd_string(), "/");
    }

    #[test]
    fn file_ops_copy_move_rename_grep() {
        let mut vfs = Vfs::new();
        vfs.write("todo.md", "buy milk").unwrap();
        vfs.write("todo.md", "water plants").unwrap();
        let hits = vfs.grep("plants");
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].0, "todo.md");
        vfs.copy("todo.md", "todo.bak").unwrap();
        assert!(vfs.cat("/todo.bak").is_ok());
        vfs.rename("todo.bak", "notes.txt").unwrap();
        assert!(vfs.cat("notes.txt").is_ok());
        assert!(vfs.cat("todo.bak").is_err());
        vfs.move_("notes.txt", "tmp/notes.txt").unwrap();
        assert!(vfs.cat("tmp/notes.txt").is_ok());
    }

    #[test]
    fn history_is_bounded_and_deduped_immediately_adjacent() {
        let home = tempfile::tempdir().unwrap();
        let mut history = History::default();
        for _ in 0..3 {
            history.push("ls");
        }
        history.push("cd /tmp");
        assert_eq!(
            history.entries,
            vec!["ls".to_string(), "cd /tmp".to_string()]
        );
        history.save(home.path()).unwrap();
        let loaded = History::load(home.path());
        assert_eq!(loaded.entries, history.entries);
    }
}
