use std::{
    env,
    path::{Path, PathBuf},
    process::Command,
};

use anyhow::{bail, Context, Result};

/// The checkout this binary was built from: walk up from the running binary
/// (`target/debug/neonet` -> repo root) then from the current directory,
/// looking for a directory that both is a git work tree and holds the crate
/// manifest. `None` when the binary is used outside any checkout (e.g.
/// `cargo install`ed).
pub fn find_repo_root() -> Option<PathBuf> {
    let mut starts = Vec::new();
    if let Ok(exe) = env::current_exe() {
        starts.push(exe.parent()?.to_path_buf());
    }
    if let Ok(cwd) = env::current_dir() {
        starts.push(cwd);
    }
    starts
        .into_iter()
        .find_map(|start| find_repo_root_from(&start))
}

fn find_repo_root_from(start: &Path) -> Option<PathBuf> {
    let mut dir = start;
    loop {
        if dir.join(".git").exists() && dir.join("Cargo.toml").is_file() {
            return Some(dir.to_path_buf());
        }
        dir = dir.parent()?;
    }
}

/// Run a `git` command with its output captured (stdout trimmed of trailing
/// newline). Non-zero exits become an error carrying git's stderr.
fn git_ln(repo: &Path, args: &[&str]) -> Result<String> {
    let out = Command::new("git")
        .arg("-C")
        .arg(repo)
        .args(args)
        .output()
        .with_context(|| format!("could not run `git {}`", args.join(" ")))?;
    if !out.status.success() {
        bail!(
            "`git {}` failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

fn short(sha: &str) -> &str {
    &sha[..sha.len().min(8)]
}

/// Update the source checkout from git and rebuild the binary.
///
/// Deliberately manual — `neonet update`, whenever *you* decide — and
/// deliberately non-destructive: it only ever `git fetch` + `git pull
/// --ff-only`, never a force reset, so a bad push can neither wedge your
/// checkout nor silently clobber uncommitted work. If a fast-forward is not
/// possible git refuses, and so do we.
///
/// The repo/branch come from, in order: `--repo`/`--branch` flags, the
/// `NEONET_UPDATE_REPO`/`NEONET_UPDATE_BRANCH` environment variables, and
/// finally the git `origin` / current branch of the checkout.
pub fn run(repo_arg: Option<&str>, branch_arg: Option<&str>, release: bool) -> Result<()> {
    if !Command::new("git")
        .arg("--version")
        .output()
        .context("could not run git — is it installed?")?
        .status
        .success()
    {
        bail!("git is not usable; `neonet update` needs it to pull the source");
    }

    let Some(repo) = find_repo_root() else {
        bail!(
            "could not find this checkout — no git repo with a Cargo.toml above the binary or the \
             current directory. Run `neonet update` from inside a clone of the source."
        );
    };
    let repo_display = repo.display();

    let repo_url = repo_arg
        .map(str::to_string)
        .or_else(|| {
            env::var("NEONET_UPDATE_REPO")
                .ok()
                .filter(|s| !s.is_empty())
        })
        .or_else(|| git_ln(&repo, &["remote", "get-url", "origin"]).ok());
    let Some(repo_url) = repo_url else {
        bail!(
            "no source repo to update from. Pass `--repo <url>`, set $NEONET_UPDATE_REPO, or add \
             a git `origin` in {repo_display}."
        );
    };

    let branch = branch_arg
        .map(str::to_string)
        .or_else(|| {
            env::var("NEONET_UPDATE_BRANCH")
                .ok()
                .filter(|s| !s.is_empty())
        })
        .or_else(|| {
            git_ln(&repo, &["rev-parse", "--abbrev-ref", "HEAD"])
                .ok()
                .filter(|b| b != "HEAD")
        });
    let Some(branch) = branch else {
        bail!(
            "could not determine which branch to follow — pass `--branch <name>` or check a \
             branch out in {repo_display}."
        );
    };

    // Keep `origin` pointing at the update source so the pull below works; a
    // divergent origin is only ever repointed, never a second remote guesses
    // at.
    match git_ln(&repo, &["remote", "get-url", "origin"]) {
        Ok(current) if current != repo_url => {
            println!("repointing origin: {current} -> {repo_url}");
            git_ln(&repo, &["remote", "set-url", "origin", &repo_url])?;
        }
        Err(_) => {
            git_ln(&repo, &["remote", "add", "origin", &repo_url])?;
        }
        _ => {}
    }

    println!("checking {repo_url} ({branch})...");
    git_ln(&repo, &["fetch", "--quiet", "origin", &branch]).with_context(|| {
        format!("could not fetch from {repo_url} ({branch}) — offline, or the URL/branch is wrong?")
    })?;
    let local = git_ln(&repo, &["rev-parse", "HEAD"])?;
    let remote = git_ln(&repo, &["rev-parse", &format!("origin/{branch}")])
        .with_context(|| format!("branch '{branch}' was not found on {repo_url}"))?;

    if local == remote {
        println!("already up to date at {}.", short(&local));
        return Ok(());
    }
    println!("update available: {} -> {}.", short(&local), short(&remote));

    let pull = Command::new("git")
        .arg("-C")
        .arg(&repo)
        .args(["pull", "--ff-only", "origin", &branch])
        .status()
        .context("could not run `git pull --ff-only`")?;
    if !pull.success() {
        bail!(
            "the pull was refused — `--ff-only` never overwrites local work. Stash or commit \
             your changes (or the history has diverged) and run `neonet update` again."
        );
    }
    println!("updated to {} in {repo_display}.", short(&remote));

    println!(
        "rebuilding the {} binary...",
        if release { "release" } else { "debug" }
    );
    let mut cargo = Command::new("cargo");
    cargo.arg("build").current_dir(&repo);
    if release {
        cargo.arg("--release");
    }
    let status = cargo
        .status()
        .context("could not run `cargo build` (is Rust/cargo installed?)")?;
    if !status.success() {
        bail!(
            "the rebuild failed. The source is updated, but the currently installed binary is \
             still the old one."
        );
    }
    println!(
        "rebuild finished — the next `{}` run uses the new code.",
        if release {
            "neonet (release build)"
        } else {
            "neonet"
        }
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn finds_repo_root_by_walking_up_to_git_and_manifest() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let nested = root.join("a/b/c");
        fs::create_dir_all(&nested).unwrap();
        // No git, no manifest -> the walk must come up empty.
        assert_eq!(find_repo_root_from(&nested), None);

        fs::create_dir(root.join(".git")).unwrap();
        fs::write(root.join("Cargo.toml"), "[package]\n").unwrap();

        assert_eq!(find_repo_root_from(&nested), Some(root.to_path_buf()));
        assert_eq!(find_repo_root_from(root), Some(root.to_path_buf()));
        assert_eq!(
            find_repo_root_from(&root.join("a/b")),
            Some(root.to_path_buf())
        );
    }
}
