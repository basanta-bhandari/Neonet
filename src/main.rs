use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use neonet::{
    app,
    bootstrap::{self, BootstrapEntry},
    identity::{Identity, PublicIdentity},
    node::{AllowList, Node},
    ssh::{self, ResolutionDirectory},
    SOFTWARE_VERSION,
};
use std::{
    env, fs, io,
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::Arc,
};

/// NeoNet — identity-based messaging, file transfer, and remote-login
/// resolution over a small, owned mesh. Run `neonet <command> --help` for
/// details on any one command.
#[derive(Parser)]
#[command(name = "neonet", version = SOFTWARE_VERSION, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Show this device's identity fingerprint, public key, and key file path.
    Whoami,
    /// List known devices from ~/.neonet/devices.json (aliases you can `connect` to).
    Devices,
    /// Resolve a device alias/fingerprint and open a real SSH session to it.
    ///
    /// Looks the id up in ~/.neonet/devices.json, then hands off to your
    /// system's `ssh` — NeoNet does not implement SSH itself, it only
    /// resolves the alias to a host.
    Connect {
        /// Alias or fingerprint from `neonet devices`.
        device_id: String,
    },
    /// SSH redirector: resolve a device and run an SSH session or one-shot
    /// remote command through the local `ssh` binary.
    ///
    /// Same resolution as `connect`, plus optional remote command words that
    /// are passed through verbatim (`neonet nsh server journalctl -u neonet`).
    Nsh {
        /// Alias or fingerprint from `neonet devices`.
        device_id: String,
        /// Remote command and arguments; omit for an interactive shell.
        #[arg(trailing_var_arg = true)]
        command: Vec<String>,
    },
    /// Send a file to a peer (alias or fingerprint from `neonet devices`).
    ///
    /// Connects to the mesh using the core nodes in a bootstrap file, then
    /// streams chunks over authenticated messages until the peer reports the
    /// transfer complete. The peer must be running a core or edge daemon.
    Send {
        /// Alias or fingerprint from `neonet devices`.
        device_id: String,
        /// File to send.
        file: PathBuf,
        /// bootstrap.json describing the core node(s) to reach it through.
        /// Defaults to NEONET_HOME/bootstrap.json.
        #[arg(long)]
        bootstrap: Option<PathBuf>,
    },
    /// Show inbound file transfers on this device and their resume state.
    Transfers,
    /// Browse a peer's shared (read-only) directory — metadata only, no writes.
    Browse {
        /// Alias or fingerprint from `neonet devices`.
        device_id: String,
        /// Relative path inside the share (default: the share root).
        path: Option<String>,
        /// bootstrap.json describing the core node(s) to reach it through.
        #[arg(long)]
        bootstrap: Option<PathBuf>,
    },
    /// Push encrypted chunks to a device's blob store, or pull them back.
    ///
    /// Chunks are encrypted on this device before leaving it; the storing core
    /// can never decrypt them. `push` prints the file id you pass to `pull`.
    #[command(subcommand)]
    Store(StoreCommand),
    /// Pull a full local copy of a file from a peer's Burrow share.
    ///
    /// The host never offers a write primitive, so this reads the file and
    /// stores it under NEONET_HOME/forked/ on this device. Files that already
    /// exist locally are overwritten.
    Fork {
        /// Alias or fingerprint from `neonet devices`.
        device_id: String,
        /// Relative path inside the share.
        path: String,
        /// bootstrap.json describing the core node(s) to reach it through.
        #[arg(long)]
        bootstrap: Option<PathBuf>,
    },
    /// Run this device as a core node: accept inbound connections and relay/store for edges.
    Core {
        /// Address to listen on, e.g. 0.0.0.0:7000
        #[arg(long)]
        listen: SocketAddr,
        /// allow-list file: a JSON array of full 64-hex public keys that this
        /// node will accept inbound connections from (see `docs/CLI.md#access-control`).
        /// Omit to accept any authenticated peer (development only — see the
        /// warning printed at startup).
        #[arg(long = "allow-file", value_name = "FILE")]
        allow_file: Option<PathBuf>,
    },
    /// Run this device as an edge node: dial out to the core(s) listed in a bootstrap file.
    Edge {
        /// Path to a bootstrap.json file: a list of
        /// {"address": "host:port", "pinned_public_key": "<hex>"} entries.
        /// See `docs/CLI.md` for the exact format and how to generate one.
        #[arg(long)]
        bootstrap: PathBuf,
    },
    /// Alias for `core` — accept inbound connections without core-specific defaults.
    Serve {
        #[arg(long)]
        listen: SocketAddr,
        #[arg(long = "allow-file", value_name = "FILE")]
        allow_file: Option<PathBuf>,
    },
    /// Copy a stored file from one core to another (replication).
    ///
    /// The file id is opaque ciphertext to both cores; the operator's device
    /// reads the chunks out of `src` and pushes them into `dst`, so neither
    /// core ever sees plaintext. `dst` must be reachable through the same mesh
    /// as `src` (in a reference deployment, every core dials the others).
    Replicate {
        /// Alias or fingerprint (from `neonet devices`) of the source core.
        src: String,
        /// Alias or fingerprint (from `neonet devices`) of the destination core.
        dst: String,
        /// File id printed by `neonet store push`.
        file_id: String,
        /// bootstrap.json describing the core node(s) to reach the mesh through.
        #[arg(long)]
        bootstrap: Option<PathBuf>,
    },
    /// Apply a revocation to a core: broadcasts a signed revoke record for a
    /// peer, which the core only applies if this device is in its operator set.
    ///
    /// Cores fail closed — an empty operator set means nobody can revoke. Add
    /// this device's public key with `neonet operator add <hex>` on each core's
    /// own NEONET_HOME first. The signature covers a per-device monotonic epoch,
    /// so a replayed broadcast is rejected as stale.
    Revoke {
        /// Alias or fingerprint (from `neonet devices`) of the core to update.
        device_id: String,
        /// Full 64-hex public key of the peer to revoke (see `neonet whoami`).
        revoked: String,
        /// bootstrap.json describing the core node(s) to reach it through.
        #[arg(long)]
        bootstrap: Option<PathBuf>,
    },
    /// Manage the local operator set — the identities authorized to revoke
    /// through this device when it runs as a core.
    #[command(subcommand)]
    Operator(OperatorCommand),
    /// Publish this device's address to a rendezvous service so remote peers
    /// can `scan` for it. Registration is signed by this device, so nobody can
    /// publish an address under your identity.
    Register {
        /// Alias or fingerprint (from `neonet devices`) of the rendezvous node.
        device_id: String,
        /// The address peers should dial (as printed in the rendezvous, e.g. 192.0.2.10:7000).
        #[arg(long)]
        addr: String,
        /// How long the registration lives before expiring (seconds).
        /// Defaults to 6h; the service clamps to [60s, 24h].
        #[arg(long)]
        ttl: Option<u32>,
        /// bootstrap.json describing the core node(s) to reach it through.
        #[arg(long)]
        bootstrap: Option<PathBuf>,
    },
    /// Ask a rendezvous service which devices are currently published, and
    /// (optionally) which are alive. `filter` is a substring of a device's
    /// public-key fingerprint.
    Scan {
        /// Alias or fingerprint (from `neonet devices`) of the rendezvous node.
        device_id: String,
        /// Optional fingerprint substring to match against.
        filter: Option<String>,
        /// Probe each hit to confirm its registration is still alive.
        #[arg(long)]
        active: bool,
        /// bootstrap.json describing the core node(s) to reach it through.
        #[arg(long)]
        bootstrap: Option<PathBuf>,
    },
    /// Run as the flash-pairing acceptor: publish a single-use pairing token
    /// and stay online until a device redeems it (or it expires).
    ///
    /// The token is shown once and exists for at most `--ttl` seconds
    /// (default 120, max 600). Whoever redeems it on *this* device is added to
    /// this device's pairing ledger (`NEONET_HOME/paired.json`). The ledger
    /// feeds `neonet pairs --as-allow` to build a core allow-list, keeping the
    /// transport gate a deliberate operator decision rather than an
    /// autorun-style silent trust.
    Pair {
        /// How long the token stays valid (seconds).
        #[arg(long)]
        ttl: Option<u64>,
        /// bootstrap.json describing the core node(s) this device dials
        /// while waiting. Defaults to NEONET_HOME/bootstrap.json.
        #[arg(long)]
        bootstrap: Option<PathBuf>,
    },
    /// Redeem an acceptor's single-use pairing token: `neonet flash <acceptor>
    /// <token>`. The acceptor recorded you as paired (see `neonet pairs`).
    Flash {
        /// Alias or fingerprint (from `neonet devices`) of the acceptor.
        device_id: String,
        /// The token printed by the acceptor's `neonet pair`.
        token: String,
        /// bootstrap.json describing the core node(s) to reach it through.
        #[arg(long)]
        bootstrap: Option<PathBuf>,
    },
    /// Show this device's pairing ledger, or emit it as an allow-list file.
    Pairs {
        /// Print the ledger as a JSON array of public keys, ready to install
        /// as `--allow-file` (see docs/CLI.md#access-control).
        #[arg(long)]
        as_allow: bool,
    },
    /// Host a lobby: this device becomes the host, prints the lobby key once,
    /// and relays members' posts for as long as it stays online. Pick the
    /// lobby's look and size here, before it starts — there is no
    /// post-start mutation (a host that wants different walls starts a new
    /// lobby). See docs/LOBBY_DESIGN.md.
    Host {
        /// The lobby's name.
        lobby_name: String,
        /// Display title members see when they join. Defaults to the lobby name.
        #[arg(long)]
        title: Option<String>,
        /// Welcome message shown to each member once, at admission.
        #[arg(long)]
        welcome: Option<String>,
        /// Hard cap on simultaneous members (the host itself doesn't count).
        #[arg(long)]
        max_members: Option<usize>,
        /// bootstrap.json describing the core node(s) this device dials
        /// while hosting. Defaults to NEONET_HOME/bootstrap.json.
        #[arg(long)]
        bootstrap: Option<PathBuf>,
    },
    /// Join a lobby hosted by another device, presenting the lobby key the
    /// host printed. Lobby key out-of-band security, same caution as any
    /// shared secret. See docs/LOBBY_DESIGN.md.
    Join {
        /// The lobby's name.
        lobby_name: String,
        /// Alias or fingerprint (from `neonet devices`) of the host device.
        host_device_id: String,
        /// The lobby key printed by the host.
        key: String,
        /// bootstrap.json describing the core node(s) to reach it through.
        #[arg(long)]
        bootstrap: Option<PathBuf>,
    },
    /// Send a private 1:1 message on a channel to any active device, or — with
    /// no message — show this device's received channel log from that peer.
    /// Runs in the encrypted transport and is separate from lobby (group)
    /// messaging; Burrow stays file exchange (see `browse` / `fork`).
    Channel {
        /// Alias or fingerprint (from `neonet devices`) of the active device.
        device_id: String,
        /// The message text. Omit to show the received channel log.
        message: Option<String>,
        /// bootstrap.json describing the core node(s) to reach it through.
        #[arg(long)]
        bootstrap: Option<PathBuf>,
    },
    /// Lobby subcommands for a member: post, log, members.
    Lobby {
        #[command(subcommand)]
        command: LobbyCommand,
    },
    /// Pull the newest code from your git remote and rebuild this binary —
    /// manually, whenever you decide, never automatically on open.
    ///
    /// Only ever fast-forwards (`git fetch` + `git pull --ff-only`): a bad
    /// push can never force-reset your checkout. If the update would clobber
    /// uncommitted changes, git refuses and so does this command.
    Update {
        /// Repo URL to pull from. Default: $NEONET_UPDATE_REPO, then git origin.
        #[arg(long)]
        repo: Option<String>,
        /// Branch to follow. Default: $NEONET_UPDATE_BRANCH, then the current branch.
        #[arg(long)]
        branch: Option<String>,
        /// Rebuild a release binary (`cargo build --release`).
        #[arg(long)]
        release: bool,
    },
}

#[derive(Subcommand)]
enum LobbyCommand {
    /// Post one encrypted text message to a lobby you joined.
    Post {
        lobby_name: String,
        text: String,
        #[arg(long)]
        bootstrap: Option<PathBuf>,
    },
    /// Show the decrypted posts this member has received in a lobby.
    Log { lobby_name: String },
    /// Ask the host which members are in a lobby right now.
    Members {
        lobby_name: String,
        #[arg(long)]
        bootstrap: Option<PathBuf>,
    },
}

#[derive(Subcommand)]
enum OperatorCommand {
    /// Add a full public key (64 hex) to this node's operator set.
    Add {
        /// 64-hex public key, e.g. the hex line from `neonet whoami`.
        public_key_hex: String,
    },
    /// Show the current operator fingerprints.
    List,
}

#[derive(Subcommand)]
enum StoreCommand {
    /// Encrypt a local file and store the opaque chunks on a device (core).
    Push {
        /// Alias or fingerprint from `neonet devices` of the storing core.
        device_id: String,
        /// File to encrypt and push.
        file: PathBuf,
        #[arg(long)]
        bootstrap: Option<PathBuf>,
    },
    /// Fetch, decrypt, and reconstruct a stored file to its original name.
    Pull {
        /// Alias or fingerprint from `neonet devices` of the holding core.
        device_id: String,
        /// File id printed by `neonet store push`.
        file_id: String,
        /// Output path. Defaults to a file named like the stored file's
        /// original, in the current directory.
        output: Option<PathBuf>,
        #[arg(long)]
        bootstrap: Option<PathBuf>,
    },
}

fn home() -> PathBuf {
    env::var_os("NEONET_HOME")
        .map(PathBuf::from)
        .or_else(|| {
            env::var_os("HOME")
                .map(PathBuf::from)
                .map(|p| p.join(".neonet"))
        })
        .unwrap_or_else(|| PathBuf::from(".neonet"))
}

fn load_identity(root: &PathBuf) -> Result<Identity> {
    fs::create_dir_all(root)
        .with_context(|| format!("could not create state directory {}", root.display()))?;
    Identity::load_or_generate(root.join("identity")).with_context(|| {
        format!(
            "could not load or generate identity under {}",
            root.display()
        )
    })
}

/// Parse a full 64-hex-char Ed25519 public key into the fixed-size array
/// identity records carry.
fn parse_public_key(hex: &str) -> Result<[u8; 32]> {
    let bytes = hex::decode(hex).with_context(|| format!("'{hex}' is not valid hex"))?;
    bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("a public key must be exactly 64 hex characters"))
}

/// Monotonic revocation counter for this device: 1, 2, 3… persisted in
/// NEONET_HOME/revoke.epoch so every broadcast is unique and replayable.
fn next_revocation_epoch(root: &Path) -> Result<u64> {
    let path = root.join("revoke.epoch");
    let next = match fs::read(&path) {
        Ok(bytes) if bytes.len() == 8 => {
            let mut raw = [0u8; 8];
            raw.copy_from_slice(&bytes);
            u64::from_le_bytes(raw).saturating_add(1)
        }
        _ => 1,
    };
    let tmp = path.with_extension("epoch.tmp");
    fs::write(&tmp, next.to_le_bytes())?;
    fs::rename(&tmp, &path)?;
    Ok(next)
}

/// Build the accepting side's allow-list. A missing `--allow-file` is the
/// "development only" case: the node accepts any authenticated peer and says so
/// loudly at startup. An `--allow-file` must be a JSON array of full 64-hex
/// public keys — fingerprints alone can't be turned back into a key to verify
/// against, so anything else is refused rather than silently downgraded.
fn allow_list(path: Option<PathBuf>) -> Result<AllowList> {
    match path {
        None => {
            eprintln!(
                "warning: no --allow-file given — this node will accept connections from ANY \
                 authenticated peer. Fine for local development; do not run this open on a \
                 public address. Create an allow-list file and pass --allow-file FILE — see \
                 docs/CLI.md#access-control."
            );
            Ok(AllowList::open())
        }
        Some(path) => {
            let bytes = fs::read(&path)
                .with_context(|| format!("could not read allow-list file {}", path.display()))?;
            let keys: Vec<String> = serde_json::from_slice(&bytes).with_context(|| {
                format!(
                    "{} is not valid allow-list JSON — expected an array of 64-hex public keys, \
                     see docs/CLI.md#access-control",
                    path.display()
                )
            })?;
            if keys.is_empty() {
                anyhow::bail!(
                    "allow-list file {} is empty — an empty list would accept nobody; add at \
                     least one full public key or drop --allow-file for development",
                    path.display()
                );
            }
            let identities = keys
                .iter()
                .map(|hex| -> Result<PublicIdentity, anyhow::Error> {
                    Ok(PublicIdentity {
                        public_key: parse_public_key(hex)?,
                    })
                })
                .collect::<anyhow::Result<Vec<_>>>()?;
            Ok(AllowList::only(identities))
        }
    }
}

fn load_devices(root: &Path) -> Result<ResolutionDirectory> {
    let path = root.join("devices.json");
    if !path.exists() {
        return Ok(ssh::empty_directory());
    }
    let bytes = fs::read(&path).with_context(|| format!("could not read {}", path.display()))?;
    serde_json::from_slice(&bytes).with_context(|| {
        format!(
            "{} is not valid device-directory JSON — see docs/CLI.md#devices",
            path.display()
        )
    })
}

/// Route one inbound message through the app-frame dispatcher and surface any
/// terminal notification the handler produced.
async fn dispatch_message(node: Arc<Node>, message: neonet::messaging::Message) {
    match neonet::app::handle(&node, &message).await {
        Ok(outcome) => {
            if let Some(text) = outcome.notify {
                println!("{text}");
            }
        }
        Err(e) => println!(
            "[neonet] message {} from {} failed to handle: {e}",
            hex::encode(message.id),
            message.sender.fingerprint()
        ),
    }
}

/// Dial to the mesh, resolve `device_id` to a full identity, and return a
/// request/response client ready to send one-shot frames. Reused by `send`,
/// `browse`, `fork`, and `store`.
async fn mesh_client(
    root: &Path,
    local_identity: Identity,
    device_id: &str,
    bootstrap: Option<PathBuf>,
) -> Result<(Arc<Node>, PublicIdentity, app::Client)> {
    let directory = load_devices(root)?;
    let record = directory.resolve(device_id).ok_or_else(|| {
        anyhow::anyhow!(
            "device '{device_id}' not found — run `neonet devices` to see known aliases, or \
             check {}/devices.json",
            root.display()
        )
    })?;
    let peer = record.identity.clone();

    let bootstrap_path = bootstrap.unwrap_or_else(|| root.join("bootstrap.json"));
    let entries = bootstrap::load(&bootstrap_path).with_context(|| {
        format!(
            "could not load bootstrap file {} — expected a JSON list of \
             {{\"address\": \"host:port\", \"pinned_public_key\": \"<hex>\"}} entries, \
             see docs/CLI.md#bootstrap",
            bootstrap_path.display()
        )
    })?;

    let node =
        Arc::new(Node::with_home(local_identity, 1024, root).context("could not initialize node")?);
    // `dial` pumps the connection for its whole lifetime, so it must run as a
    // background task: awaiting it directly would return only when the
    // connection closes. `await_any_next_hop` below waits for the dialed
    // core to register as a route instead.
    tokio::spawn({
        let node = Arc::clone(&node);
        let entries = entries.clone();
        async move {
            if let Err(e) = node.dial(&entries).await {
                eprintln!("[neonet] connection to upstream core(s) dropped: {e}");
            }
        }
    });
    node.await_any_next_hop(&[peer.clone()], std::time::Duration::from_secs(15))
        .await
        .with_context(|| {
            format!(
            "no route to device '{device_id}' — is it running a core or edge daemon connected to \
             the same mesh (the device record points at fingerprint {})?",
            peer.fingerprint()
        )
        })?;

    let client = app::Client::connect(Arc::clone(&node)).await?;
    Ok((node, peer, client))
}

/// The shell's one persistent mesh connection. Created once when the shell
/// starts (the shell is an edge node: it dials the bootstrap cores and keeps
/// them routed for its whole lifetime), then every mesh command reuses it
/// instead of re-dialing. Unsolicited inbound traffic — lobby relays, channel
/// messages, pairing redemptions, transfer-chunk pushes, rendezvous probes —
/// is handled live by the client pump and surfaced as `[neonet] ...` lines, so
/// hosting a lobby, accepting a pairing, or receiving a channel message all
/// work *while you are at the prompt*.
struct ShellMesh {
    node: Arc<Node>,
    client: app::Client,
    bootstrap_path: PathBuf,
}

impl ShellMesh {
    /// Dial out to the bootstrap core(s) once and return a client that pumps
    /// inbound traffic for the whole session. Missing bootstrap data just
    /// starts a dial-less node — mesh commands then fail with a route error
    /// and the local drive still works.
    async fn open(root: &Path, identity: Identity) -> io::Result<Self> {
        let node = Arc::new(Node::with_home(identity, 1024, root)?);
        let bootstrap_path = root.join("bootstrap.json");
        if let Ok(entries) = bootstrap::load(&bootstrap_path) {
            // `dial` pumps the connection for its whole lifetime, so it runs
            // as a background task; `peer()` below waits for a route instead.
            tokio::spawn({
                let node = Arc::clone(&node);
                async move {
                    if let Err(e) = node.dial(&entries).await {
                        eprintln!("[neonet] connection to upstream core(s) dropped: {e}");
                    }
                }
            });
        }
        let client = app::Client::connect(Arc::clone(&node)).await?;
        Ok(Self {
            node,
            client,
            bootstrap_path,
        })
    }

    fn node(&self) -> &Arc<Node> {
        &self.node
    }

    /// Resolve an alias/fingerprint to a peer and wait until the mesh can reach
    /// it through a relay core. Falls back to one opportunistic redial (the
    /// session's original dial may have dropped while the shell was idle).
    async fn peer(&self, root: &Path, device_id: &str) -> Result<PublicIdentity, String> {
        let directory = load_devices(root).map_err(|e| e.to_string())?;
        let record = directory.resolve(device_id).ok_or_else(|| {
            format!(
                "device '{device_id}' not found — run `devices` to see known aliases, or check \
                 {}/devices.json",
                root.display()
            )
        })?;
        let peer = record.identity.clone();
        let mut reached = self
            .node
            .await_any_next_hop(&[peer.clone()], std::time::Duration::from_secs(8))
            .await;
        if reached.is_err() {
            if let Ok(entries) = bootstrap::load(&self.bootstrap_path) {
                let node = Arc::clone(&self.node);
                tokio::spawn(async move {
                    let _ = node.dial(&entries).await;
                });
            }
            reached = self
                .node
                .await_any_next_hop(&[peer.clone()], std::time::Duration::from_secs(8))
                .await;
        }
        reached.map_err(|_| {
            format!(
                "no route to device '{device_id}' — is it running a core or edge daemon connected \
                 to the same mesh (the device record points at fingerprint {})?",
                peer.fingerprint()
            )
        })?;
        Ok(peer)
    }

    /// One request/response round-trip through the session's client.
    async fn call(
        &mut self,
        root: &Path,
        device_id: &str,
        frame: app::AppFrame,
    ) -> Result<neonet::messaging::Message, String> {
        let peer = self.peer(root, device_id).await?;
        self.client
            .call(&peer, frame)
            .await
            .map_err(|e| format!("no reply from '{device_id}': {e:?}"))
    }
}

/// Pull the value of `--name VALUE` out of a command's arg list.
fn flag_value(args: &[String], name: &str) -> Option<String> {
    args.iter()
        .position(|arg| arg == name)
        .and_then(|index| args.get(index + 1).cloned())
}

fn flag_usize(args: &[String], name: &str) -> Option<usize> {
    flag_value(args, name).and_then(|value| value.parse().ok())
}

/// What `channel` resolves to in the shell. The first word is treated as a
/// device alias when it matches one in devices.json; otherwise the sentence is
/// addressed to the currently mounted device (the shell's original behavior).
#[allow(dead_code)]
enum ChannelTarget {
    Alias(String),
    Nothing,
}

#[allow(dead_code)]
fn channel_target(
    root: &Path,
    words: &[String],
    mounted: Option<&Mounted>,
) -> (ChannelTarget, Option<String>) {
    if let Some(first) = words.first() {
        if load_devices(root)
            .map(|directory| directory.resolve(first).is_some())
            .unwrap_or(false)
        {
            let alias = first.clone();
            let text = if words.len() > 1 {
                Some(words[1..].join(" "))
            } else {
                None
            };
            return (ChannelTarget::Alias(alias), text);
        }
    }
    match mounted {
        Some(m) => {
            let text = if words.is_empty() {
                None
            } else {
                Some(words.join(" "))
            };
            (ChannelTarget::Alias(m.alias.clone()), text)
        }
        None => (ChannelTarget::Nothing, None),
    }
}

/// Launch a detached `neonet <subcommand>` daemon (core/serve/edge) from the
/// shell, with output redirected to `NEONET_HOME/logs/<sub>-<micros>.log` and
/// the {subcommand, pid, log} record appended to `NEONET_HOME/logs/daemons.json`
/// so `daemons`/`stop` can see it. The child keeps running after the shell is
/// quit. Returns `(pid, log_path)`.
fn spawn_daemon(root: &Path, subcommand: &str, argv: &[String]) -> Result<(u32, PathBuf)> {
    let logs_dir = root.join("logs");
    fs::create_dir_all(&logs_dir)?;
    let micros = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_micros())
        .unwrap_or_default();
    let log_path = logs_dir.join(format!("{subcommand}-{micros}.log"));
    let executable = env::current_exe().context("could not locate this binary")?;
    let log_file = fs::File::create(&log_path)
        .with_context(|| format!("could not open daemon log {}", log_path.display()))?;
    let stdout = log_file
        .try_clone()
        .context("could not duplicate the daemon log handle")?;
    let child = std::process::Command::new(&executable)
        .arg(subcommand)
        .args(argv)
        .env("NEONET_HOME", root)
        .stdout(std::process::Stdio::from(stdout))
        .stderr(std::process::Stdio::from(log_file))
        .spawn()
        .with_context(|| format!("could not spawn `neonet {subcommand}`"))?;
    let pid = child.id();

    #[derive(serde::Serialize, serde::Deserialize)]
    struct Daemon {
        name: String,
        pid: u32,
        log: String,
    }
    let daemons_path = logs_dir.join("daemons.json");
    let mut daemons: Vec<Daemon> = if daemons_path.exists() {
        serde_json::from_str(
            &fs::read_to_string(&daemons_path).context("could not read daemons.json")?,
        )
        .unwrap_or_default()
    } else {
        Vec::new()
    };
    daemons.push(Daemon {
        name: subcommand.to_string(),
        pid,
        log: log_path.display().to_string(),
    });
    let bytes = serde_json::to_vec(&daemons)?;
    let tmp = daemons_path.with_extension("tmp");
    fs::write(&tmp, bytes)?;
    fs::rename(tmp, daemons_path)?;
    Ok((pid, log_path))
}

fn daemons_path(root: &Path) -> PathBuf {
    root.join("logs").join("daemons.json")
}

fn list_daemons(root: &Path) -> Vec<(String, u32, String)> {
    let path = daemons_path(root);
    if !path.exists() {
        return Vec::new();
    }
    #[derive(serde::Deserialize)]
    struct Daemon {
        name: String,
        pid: u32,
        log: String,
    }
    match serde_json::from_str::<Vec<Daemon>>(&fs::read_to_string(path).unwrap_or_default()) {
        Ok(daemons) => daemons
            .into_iter()
            .map(|d| (d.name, d.pid, d.log))
            .collect(),
        Err(_) => Vec::new(),
    }
}

fn save_daemons(root: &Path, daemons: &[(String, u32, String)]) -> io::Result<()> {
    #[derive(serde::Serialize)]
    struct Daemon<'a> {
        name: &'a str,
        pid: u32,
        log: &'a str,
    }
    let mapped = daemons
        .iter()
        .map(|(name, pid, log)| Daemon {
            name,
            pid: *pid,
            log,
        })
        .collect::<Vec<_>>();
    let bytes = serde_json::to_vec(&mapped)?;
    let path = daemons_path(root);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let tmp = path.with_extension("tmp");
    fs::write(&tmp, bytes)?;
    fs::rename(tmp, path)
}

/// `Identity` is not `Clone`, so the shell reloads this device's key from disk
/// for each mesh operation instead of moving the session's copy away.
fn reload_identity(root: &Path) -> Identity {
    Identity::load_or_generate(root.join("identity"))
        .expect("identity file vanished during the shell session")
}

/// Join a command-line path onto the mounted device's current (relative)
/// directory, normalizing `.`/`..`/repeats. An empty string means the share
/// root, which Burrow addresses as `"."`.
#[allow(dead_code)]
fn join_remote_path(cwd: &str, target: &str) -> String {
    let mut parts: Vec<&str> = if cwd.is_empty() {
        Vec::new()
    } else {
        cwd.split('/').collect()
    };
    for segment in target.split('/') {
        match segment {
            "" | "." => {}
            ".." => {
                parts.pop();
            }
            name => parts.push(name),
        }
    }
    parts.join("/")
}

#[allow(dead_code)]
fn remote_cwd_display(cwd: &str) -> String {
    if cwd.is_empty() {
        "/".to_string()
    } else {
        format!("/{cwd}")
    }
}

/// A mounted remote drive: which device a Burrow share is attached to.
#[allow(dead_code)]
struct Mounted {
    alias: String,
}

/// Shared by the shell's remote `ls`, `cd`, and `pwd`: list a Burrow path and
/// return (name, kind, size) rows or the host's error message.
#[allow(dead_code)]
async fn shell_remote_list(
    session: &mut ShellMesh,
    root: &Path,
    alias: &str,
    path: &str,
) -> Result<Vec<(String, neonet::burrow::EntryKind, u64)>, String> {
    let reply = session
        .call(
            root,
            alias,
            neonet::app::AppFrame::Burrow(neonet::app::burrow::BurrowFrame::List {
                path: path.to_string(),
            }),
        )
        .await
        .map_err(|e| format!("'{alias}' unreachable: {e}"))?;
    match neonet::app::AppFrame::decode(&reply.payload) {
        neonet::app::AppFrame::Burrow(neonet::app::burrow::BurrowFrame::Listing {
            entries,
            ..
        }) => Ok(entries
            .into_iter()
            .map(|entry| (entry.name, entry.kind, entry.size))
            .collect()),
        neonet::app::AppFrame::Burrow(neonet::app::burrow::BurrowFrame::Error {
            message, ..
        }) => Err(message),
        other => Err(format!("unexpected reply from '{alias}': {other:?}")),
    }
}

/// Read a remote Burrow file's bytes (used by the shell's `cat` and `get`).
#[allow(dead_code)]
async fn shell_remote_read(
    session: &mut ShellMesh,
    root: &Path,
    alias: &str,
    path: &str,
) -> Result<Vec<u8>, String> {
    let reply = session
        .call(
            root,
            alias,
            neonet::app::AppFrame::Burrow(neonet::app::burrow::BurrowFrame::Read {
                path: path.to_string(),
            }),
        )
        .await
        .map_err(|e| format!("'{alias}' unreachable: {e}"))?;
    match neonet::app::AppFrame::decode(&reply.payload) {
        neonet::app::AppFrame::Burrow(neonet::app::burrow::BurrowFrame::Content {
            bytes, ..
        }) => Ok(bytes),
        neonet::app::AppFrame::Burrow(neonet::app::burrow::BurrowFrame::Error {
            message, ..
        }) => Err(message),
        other => Err(format!("unexpected reply from '{alias}': {other:?}")),
    }
}

async fn run_server(node: Arc<Node>, addr: SocketAddr, allow: AllowList) -> Result<()> {
    let mut inbox = node.register_local().await;
    println!("NeoNet listening on {addr}");
    println!("identity fingerprint: {}", node.identity().fingerprint());
    println!("public key: {}", hex::encode(node.identity().public_key));

    let server = tokio::spawn({
        let node = Arc::clone(&node);
        async move { node.serve(addr, allow).await }
    });

    while let Some(message) = inbox.recv().await {
        dispatch_message(Arc::clone(&node), message).await;
    }

    server.abort();
    Ok(())
}

async fn run_edge(node: Arc<Node>, bootstrap_entries: Vec<BootstrapEntry>) -> Result<()> {
    let mut inbox = node.register_local().await;
    println!("NeoNet edge identity: {}", node.identity().fingerprint());
    println!(
        "connecting to {} configured core node(s)...",
        bootstrap_entries.len()
    );

    let dial = tokio::spawn({
        let node = Arc::clone(&node);
        async move { node.dial(&bootstrap_entries).await }
    });

    tokio::pin!(dial);
    loop {
        tokio::select! {
            result = &mut dial => {
                result.context("edge dial task panicked")?.context("could not connect to any configured core node")?;
                break;
            }
            message = inbox.recv() => {
                match message {
                    Some(message) => dispatch_message(Arc::clone(&node), message).await,
                    None => break,
                }
            }
        }
    }
    Ok(())
}

async fn run() -> Result<()> {
    let cli = Cli::parse();
    let root = home();
    let local_identity = load_identity(&root)?;

    match cli.command {
        Some(Command::Whoami) => {
            println!("NeoNet {SOFTWARE_VERSION}");
            println!(
                "identity fingerprint: {}",
                local_identity.public().fingerprint()
            );
            println!(
                "public key: {}",
                hex::encode(local_identity.public().public_key)
            );
            println!("identity key: {}", local_identity.path().display());
        }
        Some(Command::Devices) => {
            let directory = load_devices(&root)?;
            let devices = ssh::devices(&directory);
            if devices.is_empty() {
                println!(
                    "No devices configured yet. Add entries to {}/devices.json — see docs/CLI.md#devices.",
                    root.display()
                );
            } else {
                for (alias, fingerprint) in devices {
                    println!("{alias}\t{fingerprint}");
                }
            }
        }
        Some(Command::Connect { device_id }) => {
            let directory = load_devices(&root)?;
            ssh::connect(&directory, &device_id, &[]).with_context(|| {
                format!(
                    "could not resolve or connect to '{device_id}' — run `neonet devices` to see \
                     known aliases, or check {}/devices.json",
                    root.display()
                )
            })?;
        }
        Some(Command::Nsh { device_id, command }) => {
            let directory = load_devices(&root)?;
            let status = ssh::connect(&directory, &device_id, &command).with_context(|| {
                format!(
                    "could not resolve or run a session to '{device_id}' — run `neonet devices` \
                     to see known aliases, or check {}/devices.json",
                    root.display()
                )
            })?;
            if let Some(code) = status.code() {
                std::process::exit(code);
            }
        }
        Some(Command::Send {
            device_id,
            file,
            bootstrap,
        }) => {
            if !file.exists() {
                anyhow::bail!("file not found: {}", file.display());
            }
            let (_node, peer, mut client) =
                mesh_client(&root, local_identity, &device_id, bootstrap).await?;
            let started = std::time::Instant::now();
            let state = neonet::app::files::send_file_and_wait(
                &peer,
                &mut client,
                file.clone(),
                std::time::Duration::from_secs(120),
            )
            .await?;
            let elapsed = started.elapsed().as_secs();
            if state.complete() {
                println!(
                    "sent {} to {}: {} of {} chunks verified in {elapsed}s",
                    file.display(),
                    device_id,
                    state.verified_chunks.len(),
                    state.manifest.chunks.len(),
                );
            } else if state.lost_chunks.is_empty() {
                println!(
                    "partially sent {} to {}: {} of {} chunks verified in {elapsed}s (peer has not \
                     finished confirming; run `neonet send` again to resume, or wait)",
                    file.display(),
                    device_id,
                    state.verified_chunks.len(),
                    state.manifest.chunks.len(),
                );
            }
        }
        Some(Command::Browse {
            device_id,
            path,
            bootstrap,
        }) => {
            let (_node, peer, mut client) =
                mesh_client(&root, local_identity, &device_id, bootstrap).await?;
            let path = path.unwrap_or_else(|| ".".to_string());
            let reply = client
                .call(
                    &peer,
                    neonet::app::AppFrame::Burrow(neonet::app::burrow::BurrowFrame::List {
                        path: path.clone(),
                    }),
                )
                .await?;
            match neonet::app::AppFrame::decode(&reply.payload) {
                neonet::app::AppFrame::Burrow(neonet::app::burrow::BurrowFrame::Listing {
                    entries,
                    ..
                }) => {
                    if entries.is_empty() {
                        println!("(empty)");
                    }
                    for entry in entries {
                        let suffix = match entry.kind {
                            neonet::burrow::EntryKind::File => "",
                            neonet::burrow::EntryKind::Directory => "/",
                            neonet::burrow::EntryKind::Symlink => "@",
                        };
                        println!("{}{}\t{}", entry.name, suffix, entry.size);
                    }
                }
                neonet::app::AppFrame::Burrow(neonet::app::burrow::BurrowFrame::Error {
                    message,
                    ..
                }) => anyhow::bail!("browse failed on the host: {message}"),
                other => anyhow::bail!("unexpected reply to browse: {other:?}"),
            }
        }
        Some(Command::Fork {
            device_id,
            path,
            bootstrap,
        }) => {
            let (_node, peer, mut client) =
                mesh_client(&root, local_identity, &device_id, bootstrap).await?;
            let reply = client
                .call(
                    &peer,
                    neonet::app::AppFrame::Burrow(neonet::app::burrow::BurrowFrame::Read {
                        path: path.clone(),
                    }),
                )
                .await?;
            match neonet::app::AppFrame::decode(&reply.payload) {
                neonet::app::AppFrame::Burrow(neonet::app::burrow::BurrowFrame::Content {
                    bytes,
                    ..
                }) => {
                    let destination = root.join("forked").join(&path);
                    if let Some(parent) = destination.parent() {
                        fs::create_dir_all(parent)?;
                    }
                    fs::write(&destination, bytes)?;
                    println!("forked {path} to {}", destination.display());
                }
                neonet::app::AppFrame::Burrow(neonet::app::burrow::BurrowFrame::Error {
                    message,
                    ..
                }) => anyhow::bail!("fork failed on the host: {message}"),
                other => anyhow::bail!("unexpected reply to fork: {other:?}"),
            }
        }
        Some(Command::Store(store_command)) => match store_command {
            StoreCommand::Push {
                device_id,
                file,
                bootstrap,
            } => {
                if !file.exists() {
                    anyhow::bail!("file not found: {}", file.display());
                }
                let (_node, peer, mut client) =
                    mesh_client(&root, local_identity, &device_id, bootstrap).await?;

                let (manifest, chunks) = neonet::files::build_manifest(
                    &file,
                    client.node().local(),
                    neonet::files::DEFAULT_CHUNK_SIZE,
                )
                .map_err(|e| anyhow::anyhow!(e.to_string()))?;
                let file_id = neonet::files::manifest_id(&manifest);

                let key = neonet::storage::LocalKeyStore::new(root.join("storage.key"))
                    .load_or_generate()
                    .map_err(|e| anyhow::anyhow!(e.to_string()))?;
                let encrypted = chunks
                    .iter()
                    .map(|chunk| {
                        neonet::storage::encrypt_chunk(&key, chunk)
                            .map_err(|e| anyhow::anyhow!(e.to_string()))
                    })
                    .collect::<Result<Vec<_>, _>>()?;

                neonet::app::storage::push_chunks(
                    &peer,
                    &mut client,
                    &file_id,
                    &manifest,
                    &encrypted,
                )
                .await
                .with_context(|| format!("could not store {} on {device_id}", file.display()))?;
                println!(
                    "stored {} on {} (file id {file_id})",
                    file.display(),
                    device_id
                );
            }
            StoreCommand::Pull {
                device_id,
                file_id,
                output,
                bootstrap,
            } => {
                let (_node, peer, mut client) =
                    mesh_client(&root, local_identity, &device_id, bootstrap).await?;
                let (manifest, chunks) =
                    neonet::app::storage::pull_chunks(&peer, &mut client, &file_id)
                        .await
                        .with_context(|| format!("could not fetch {file_id} from {device_id}"))?;

                let key = neonet::storage::LocalKeyStore::new(root.join("storage.key"))
                    .load_or_generate()
                    .map_err(|e| anyhow::anyhow!(e.to_string()))?;
                let plaintext = chunks
                    .iter()
                    .map(|encrypted| {
                        neonet::storage::decrypt_chunk(&key, encrypted)
                            .map_err(|e| anyhow::anyhow!(e.to_string()))
                    })
                    .collect::<Result<Vec<_>, _>>()?;

                let destination = output.unwrap_or_else(|| PathBuf::from(&manifest.name));
                neonet::files::reconstruct(&manifest, &plaintext, &destination)
                    .map_err(|e| anyhow::anyhow!(e.to_string()))?;
                println!(
                    "restored {file_id} from {device_id} to {}",
                    destination.display()
                );
            }
        },
        Some(Command::Replicate {
            src,
            dst,
            file_id,
            bootstrap,
        }) => {
            let directory = load_devices(&root)?;
            let dst_identity = directory
                .resolve(&dst)
                .ok_or_else(|| anyhow::anyhow!("device '{dst}' not found in devices.json"))?
                .identity
                .clone();
            let (_node, src_identity, mut client) =
                mesh_client(&root, local_identity, &src, bootstrap).await?;
            let (manifest, chunks) =
                neonet::app::storage::pull_chunks(&src_identity, &mut client, &file_id)
                    .await
                    .with_context(|| format!("could not read {file_id} from {src}"))?;
            neonet::app::storage::push_chunks(
                &dst_identity,
                &mut client,
                &file_id,
                &manifest,
                &chunks,
            )
            .await
            .with_context(|| format!("could not write {file_id} to {dst}"))?;
            println!(
                "replicated {file_id} ({} chunks) from {src} to {dst}",
                chunks.len()
            );
        }
        Some(Command::Revoke {
            device_id,
            revoked,
            bootstrap,
        }) => {
            let revoked_identity = PublicIdentity {
                public_key: parse_public_key(&revoked)?,
            };
            let epoch = next_revocation_epoch(&root)?;
            let payload = neonet::app::core::revoke_payload(epoch, &revoked_identity);
            let signature = local_identity.sign(&payload);
            let (_node, peer, mut client) =
                mesh_client(&root, local_identity, &device_id, bootstrap).await?;
            let reply = client
                .call(
                    &peer,
                    neonet::app::AppFrame::Core(neonet::app::core::CoreFrame::RevokeBroadcast {
                        revoked: revoked_identity,
                        epoch,
                        signature,
                    }),
                )
                .await?;
            match neonet::app::AppFrame::decode(&reply.payload) {
                neonet::app::AppFrame::Core(neonet::app::core::CoreFrame::RevokeAck { epoch }) => {
                    println!("{device_id} acknowledged revocation epoch {epoch}");
                }
                neonet::app::AppFrame::Core(neonet::app::core::CoreFrame::RevokeRefuse {
                    epoch,
                    reason,
                }) => anyhow::bail!("{device_id} refused revocation epoch {epoch}: {reason}",),
                other => anyhow::bail!("unexpected reply to revoke: {other:?}"),
            }
        }
        Some(Command::Operator(operator_command)) => match operator_command {
            OperatorCommand::Add { public_key_hex } => {
                let identity = PublicIdentity {
                    public_key: parse_public_key(&public_key_hex)?,
                };
                let node = Node::new(local_identity, 16).context("could not open node state")?;
                neonet::app::core::set_operator(&node, &identity)?;
                println!(
                    "added {} to the operator set at {} (this node only)",
                    identity.fingerprint(),
                    root.join("operators.json").display()
                );
            }
            OperatorCommand::List => {
                let node = Node::new(local_identity, 16).context("could not open node state")?;
                if neonet::app::core::operators(&node).is_empty() {
                    println!(
                        "operator set is empty — no one can revoke through this node (fail closed). \
                         Add a key with `neonet operator add <hex>`."
                    );
                } else {
                    for fingerprint in neonet::app::core::operators(&node) {
                        println!("{fingerprint}");
                    }
                }
            }
        },
        Some(Command::Register {
            device_id,
            addr,
            ttl,
            bootstrap,
        }) => {
            if !addr.contains(':') {
                anyhow::bail!(
                    "--addr must be a host:port peers can dial back, e.g. 192.0.2.10:7000"
                );
            }
            let (_node, peer, mut client) =
                mesh_client(&root, local_identity, &device_id, bootstrap).await?;
            let frame = match ttl {
                Some(ttl) => neonet::app::rendezvous::register_frame_with_ttl(
                    client.node(),
                    addr.clone(),
                    ttl,
                ),
                None => neonet::app::rendezvous::register_frame(client.node(), addr.clone()),
            };
            let reply = client
                .call(&peer, neonet::app::AppFrame::Rendezvous(frame))
                .await?;
            match neonet::app::AppFrame::decode(&reply.payload) {
                neonet::app::AppFrame::Rendezvous(
                    neonet::app::rendezvous::RendezvousFrame::Registered,
                ) => {
                    println!("registered {addr} with {device_id}");
                }
                neonet::app::AppFrame::Rendezvous(
                    neonet::app::rendezvous::RendezvousFrame::Error { message },
                ) => anyhow::bail!("{device_id} refused the registration: {message}"),
                other => anyhow::bail!("unexpected reply to register: {other:?}"),
            }
        }
        Some(Command::Scan {
            device_id,
            filter,
            active,
            bootstrap,
        }) => {
            let (_node, peer, mut client) =
                mesh_client(&root, local_identity, &device_id, bootstrap).await?;
            let reply = client
                .call(
                    &peer,
                    neonet::app::AppFrame::Rendezvous(
                        neonet::app::rendezvous::RendezvousFrame::List,
                    ),
                )
                .await?;
            let records = match neonet::app::AppFrame::decode(&reply.payload) {
                neonet::app::AppFrame::Rendezvous(
                    neonet::app::rendezvous::RendezvousFrame::ListResult { records },
                ) => records,
                neonet::app::AppFrame::Rendezvous(
                    neonet::app::rendezvous::RendezvousFrame::Error { message },
                ) => anyhow::bail!("{device_id} could not enumerate: {message}"),
                other => anyhow::bail!("unexpected reply to scan: {other:?}"),
            };
            let filter = filter.unwrap_or_default().to_lowercase();
            let mut hits: Vec<_> = records
                .iter()
                .filter(|record| {
                    let fingerprint = record.identity.fingerprint().to_lowercase();
                    filter.is_empty()
                        || fingerprint.contains(&filter)
                        || record.address.to_lowercase().contains(&filter)
                })
                .collect();
            hits.sort_by_key(|record| record.identity.fingerprint());

            if active {
                let mut live: Vec<&neonet::app::rendezvous::EndpointRecord> = Vec::new();
                for record in &hits {
                    let reply = client
                        .call(
                            &peer,
                            neonet::app::AppFrame::Rendezvous(
                                neonet::app::rendezvous::RendezvousFrame::Probe {
                                    fingerprint: record.identity.fingerprint(),
                                },
                            ),
                        )
                        .await?;
                    if let neonet::app::AppFrame::Rendezvous(
                        neonet::app::rendezvous::RendezvousFrame::ProbeResult { alive, .. },
                    ) = neonet::app::AppFrame::decode(&reply.payload)
                    {
                        if alive {
                            live.push(record);
                        } else {
                            println!(
                                "{} @ {} (stale)",
                                record.identity.fingerprint(),
                                record.address
                            );
                        }
                    }
                }
                hits = live;
            }

            if hits.is_empty() {
                println!(
                    "(no devices registered{})",
                    if filter.is_empty() {
                        String::new()
                    } else {
                        format!(" matching '{filter}'")
                    }
                );
            }
            for record in &hits {
                println!("{} @ {}", record.identity.fingerprint(), record.address);
            }
        }
        Some(Command::Pair { ttl, bootstrap }) => {
            let entries = bootstrap::load(bootstrap.unwrap_or_else(|| root.join("bootstrap.json")))
                .with_context(|| {
                    "could not load bootstrap file — expected a JSON list of \
                         {\"address\": \"host:port\", \"pinned_public_key\": \"<hex>\"} entries, \
                         see docs/CLI.md#bootstrap"
                })?;
            let token = neonet::pair::issue_token(&root, ttl)
                .with_context(|| "could not issue a pairing token")?;
            println!(
                "pairing token: {token}  (single use; {ttl_or_default}s; presented with `neonet flash <device> {token}`)",
                ttl_or_default = ttl.unwrap_or(120),
            );
            let node =
                Arc::new(Node::new(local_identity, 1024).context("could not initialize node")?);
            println!(
                "accepting pairings. identity: {}",
                node.identity().fingerprint()
            );
            run_edge(node, entries).await?;
        }
        Some(Command::Flash {
            device_id,
            token,
            bootstrap,
        }) => {
            if token.is_empty() {
                anyhow::bail!("no token given");
            }
            let (_node, peer, mut client) =
                mesh_client(&root, local_identity, &device_id, bootstrap).await?;
            let reply = client
                .call(
                    &peer,
                    neonet::app::AppFrame::Pair(neonet::app::pair::PairFrame::Redeem {
                        token: token.clone(),
                    }),
                )
                .await?;
            match neonet::app::AppFrame::decode(&reply.payload) {
                neonet::app::AppFrame::Pair(neonet::app::pair::PairFrame::Redeemed {
                    fingerprint,
                }) => {
                    println!("{device_id} paired {fingerprint}");
                }
                neonet::app::AppFrame::Pair(neonet::app::pair::PairFrame::Error { message }) => {
                    anyhow::bail!("{device_id} refused the token: {message}")
                }
                other => anyhow::bail!("unexpected reply to flash: {other:?}"),
            }
        }
        Some(Command::Pairs { as_allow }) => {
            if as_allow {
                let keys = neonet::pair::paired_devices(&root)
                    .iter()
                    .map(|record| hex::encode(record.public_key))
                    .collect::<Vec<String>>();
                println!(
                    "{}",
                    serde_json::to_string_pretty(&keys)
                        .context("could not serialize allow-list")?
                );
            } else {
                let paired = neonet::pair::paired_devices(&root);
                if paired.is_empty() {
                    println!("no pairings recorded yet — run `neonet pair` on the acceptor and `neonet flash` on a requester.");
                } else {
                    for record in paired {
                        println!(
                            "{}\t{}\t{}",
                            record.fingerprint,
                            hex::encode(record.public_key),
                            record.paired_at
                        );
                    }
                }
            }
        }
        Some(Command::Host {
            lobby_name,
            title,
            welcome,
            max_members,
            bootstrap,
        }) => {
            let entries = bootstrap::load(bootstrap.unwrap_or_else(|| root.join("bootstrap.json")))
                .with_context(|| {
                    "could not load bootstrap file — expected a JSON list of \
                     {\"address\": \"host:port\", \"pinned_public_key\": \"<hex>\"} entries, \
                     see docs/CLI.md#bootstrap"
                })?;
            let key = neonet::lobby::new_key();
            let key_hex = hex::encode(key);
            let node =
                Arc::new(Node::new(local_identity, 1024).context("could not initialize node")?);
            // `Node::new` keys the host state under the identity's parent
            // directory (`NEONET_HOME/identity`), not NEONET_HOME itself, so
            // the lobby must be registered against `node.home()` — otherwise
            // every Join is refused with "no lobby named ... is hosted here".
            neonet::app::lobby::register_host(
                node.home(),
                &lobby_name,
                &key_hex,
                neonet::app::lobby::LobbyOptions {
                    title: title.clone().unwrap_or_default(),
                    welcome: welcome.clone().unwrap_or_default(),
                    max_members,
                },
            );
            println!(
                "hosting lobby '{}' ({title}) — give members this key and they \
                 will be admitted when presented:",
                lobby_name,
                title = title.as_deref().unwrap_or(&lobby_name),
            );
            if let Some(welcome) = &welcome {
                println!("welcome message: {welcome}");
            }
            if let Some(cap) = max_members {
                println!("seat cap: {cap} members (the host does not count)");
            }
            println!("  {key_hex}");
            println!(
                "members run: neonet join {lobby_name:?} {} {key_hex}",
                node.identity().fingerprint()
            );
            run_edge(node, entries).await?;
        }
        Some(Command::Join {
            lobby_name,
            host_device_id,
            key,
            bootstrap,
        }) => {
            if key.is_empty() {
                anyhow::bail!("no lobby key given");
            }
            let (_node, host_peer, mut client) =
                mesh_client(&root, local_identity, &host_device_id, bootstrap).await?;
            let reply = client
                .call(
                    &host_peer,
                    neonet::app::AppFrame::Lobby(neonet::app::lobby::LobbyFrame::Join {
                        lobby_name: lobby_name.clone(),
                        key: key.clone(),
                    }),
                )
                .await?;
            match neonet::app::AppFrame::decode(&reply.payload) {
                neonet::app::AppFrame::Lobby(neonet::app::lobby::LobbyFrame::Joined {
                    lobby_name,
                    title,
                    welcome,
                }) => {
                    neonet::lobby::add_to_roster(
                        &root,
                        neonet::lobby::MemberLobby {
                            name: lobby_name.clone(),
                            host_alias: host_device_id.clone(),
                            host_fingerprint: host_peer.fingerprint(),
                            key_hex: key.clone(),
                            title: title.clone(),
                            welcome: welcome.clone(),
                        },
                    )
                    .with_context(|| "could not record the lobby in the local roster")?;
                    println!(
                        "joined lobby '{lobby_name}' ({})",
                        if title.is_empty() {
                            &lobby_name
                        } else {
                            &title
                        },
                    );
                    if !title.is_empty() && title != lobby_name {
                        println!("lobby title: {title}");
                    }
                    if !welcome.is_empty() {
                        println!("{welcome}");
                    }
                }
                neonet::app::AppFrame::Lobby(neonet::app::lobby::LobbyFrame::Refuse {
                    message,
                }) => {
                    anyhow::bail!("{host_device_id} refused the lobby key: {message}")
                }
                other => anyhow::bail!("unexpected reply to join: {other:?}"),
            }
        }
        Some(Command::Channel {
            device_id,
            message,
            bootstrap,
        }) => {
            let (_node, peer, mut client) =
                mesh_client(&root, local_identity, &device_id, bootstrap).await?;
            match message {
                None => {
                    let lines = neonet::lobby::read_channel(&root, &peer.fingerprint());
                    if lines.is_empty() {
                        println!("no channel messages with {} yet.", peer.fingerprint());
                    } else {
                        for line in lines {
                            println!("{}\t{}\t{}", line.at, line.sender, line.text);
                        }
                    }
                }
                Some(text) => {
                    let reply = client
                        .call(
                            &peer,
                            neonet::app::AppFrame::Channel(
                                neonet::app::lobby::ChannelFrame::Send { text: text.clone() },
                            ),
                        )
                        .await?;
                    match neonet::app::AppFrame::decode(&reply.payload) {
                        neonet::app::AppFrame::Channel(neonet::app::lobby::ChannelFrame::Ack {
                            at,
                        }) => {
                            println!("channel message to {} acked at {at}.", peer.fingerprint());
                        }
                        other => anyhow::bail!("unexpected reply to channel: {other:?}"),
                    }
                }
            }
        }
        Some(Command::Lobby {
            command:
                LobbyCommand::Post {
                    lobby_name,
                    text,
                    bootstrap,
                },
        }) => {
            let roster = neonet::lobby::find_roster(&root, &lobby_name).with_context(|| {
                format!(
                    "not a member of lobby '{lobby_name}' — check {}/lobbies/roster.json or \
                     `neonet join` it first",
                    root.display()
                )
            })?;
            let key = hex::decode(&roster.key_hex)
                .ok()
                .and_then(|bytes| bytes.try_into().ok())
                .context("lobby roster holds a corrupt key")?;
            let (nonce, ciphertext) = neonet::lobby::encrypt(&key, text.as_bytes())
                .context("could not encrypt the post")?;
            let (_node, host_peer, mut client) =
                mesh_client(&root, local_identity, &roster.host_alias, bootstrap).await?;
            let reply = client
                .call(
                    &host_peer,
                    neonet::app::AppFrame::Lobby(neonet::app::lobby::LobbyFrame::Post {
                        lobby_name: lobby_name.clone(),
                        key: roster.key_hex.clone(),
                        nonce,
                        ciphertext,
                    }),
                )
                .await?;
            match neonet::app::AppFrame::decode(&reply.payload) {
                neonet::app::AppFrame::Lobby(neonet::app::lobby::LobbyFrame::Posted {
                    relayed,
                    ..
                }) => {
                    println!("posted to '{lobby_name}' (relayed to {relayed} member(s)).");
                }
                neonet::app::AppFrame::Lobby(neonet::app::lobby::LobbyFrame::Refuse {
                    message,
                }) => {
                    anyhow::bail!("the lobby refused the post: {message}")
                }
                other => anyhow::bail!("unexpected reply to post: {other:?}"),
            }
        }
        Some(Command::Lobby {
            command: LobbyCommand::Log { lobby_name },
        }) => {
            let roster = neonet::lobby::find_roster(&root, &lobby_name).with_context(|| {
                format!("not a member of lobby '{lobby_name}' — `neonet join` it first",)
            })?;
            let lines = neonet::lobby::read_lobby(&root, &lobby_name);
            if lines.is_empty() {
                println!(
                    "lobby '{lobby_name}' (host {}) has no received posts logged yet.",
                    roster.host_fingerprint
                );
            } else {
                for line in lines {
                    println!("{}\t{}\t{}", line.at, line.sender, line.text);
                }
            }
        }
        Some(Command::Lobby {
            command:
                LobbyCommand::Members {
                    lobby_name,
                    bootstrap,
                },
        }) => {
            let roster = neonet::lobby::find_roster(&root, &lobby_name).with_context(|| {
                format!("not a member of lobby '{lobby_name}' — `neonet join` it first",)
            })?;
            let (_node, host_peer, mut client) =
                mesh_client(&root, local_identity, &roster.host_alias, bootstrap).await?;
            let reply = client
                .call(
                    &host_peer,
                    neonet::app::AppFrame::Lobby(neonet::app::lobby::LobbyFrame::Members {
                        lobby_name: lobby_name.clone(),
                    }),
                )
                .await?;
            match neonet::app::AppFrame::decode(&reply.payload) {
                neonet::app::AppFrame::Lobby(neonet::app::lobby::LobbyFrame::MemberList {
                    fingerprints,
                }) => {
                    let fingerprints = if fingerprints.is_empty() {
                        vec!["<none>".to_string()]
                    } else {
                        fingerprints
                    };
                    for fingerprint in fingerprints {
                        println!("{fingerprint}");
                    }
                }
                other => anyhow::bail!("unexpected reply to members: {other:?}"),
            }
        }
        Some(Command::Transfers) => {
            let transfers =
                neonet::files::list_transfers(&root).context("could not scan inbound transfers")?;
            if transfers.is_empty() {
                println!("No inbound transfers recorded on this device yet.");
            } else {
                for transfer in transfers {
                    let status = if transfer.verified == transfer.total {
                        "complete"
                    } else {
                        "incomplete"
                    };
                    println!(
                        "{}\t{}\t{}/{}\t{} lost\t{}",
                        transfer.id,
                        transfer.name,
                        transfer.verified,
                        transfer.total,
                        transfer.lost,
                        status,
                    );
                }
            }
        }
        Some(Command::Core { listen, allow_file })
        | Some(Command::Serve { listen, allow_file }) => {
            let allow = allow_list(allow_file)?;
            let node =
                Arc::new(Node::new(local_identity, 1024).context("could not initialize node")?);
            run_server(node, listen, allow).await?;
        }
        Some(Command::Edge {
            bootstrap: bootstrap_path,
        }) => {
            let entries = bootstrap::load(&bootstrap_path).with_context(|| {
                format!(
                    "could not load bootstrap file {} — expected a JSON list of \
                     {{\"address\": \"host:port\", \"pinned_public_key\": \"<hex>\"}} entries, \
                     see docs/CLI.md#bootstrap",
                    bootstrap_path.display()
                )
            })?;
            let node =
                Arc::new(Node::new(local_identity, 1024).context("could not initialize node")?);
            run_edge(node, entries).await?;
        }
        None => {
            neonet::shell::boot();
            neonet::shell::home(None);
            use neonet::shell::{BOLD, RESET};

            let mut history = neonet::shell::History::load(&root);
            let mut clock = false;

            // One persistent mesh session for the whole shell: this shell is
            // an edge node, hosting lobbies, accepting pairings, and receiving
            // relays/channel messages live while you type.
            let mut session = match ShellMesh::open(&root, reload_identity(&root)).await {
                Ok(session) => session,
                Err(err) => {
                    println!(
                        "{}{}{}",
                        neonet::shell::RED,
                        format_args!("mesh session failed to start: {err}"),
                        neonet::shell::RESET
                    );
                    return Ok(());
                }
            };
            if !root.join("bootstrap.json").exists() {
                println!(
                    "{}note: no bootstrap.json yet — mesh commands can't route until you add \
                     one (see docs/CLI.md#bootstrap).{}",
                    neonet::shell::YELLOW,
                    neonet::shell::RESET
                );
            }

            let (tx, mut rx) = tokio::sync::mpsc::channel::<Option<String>>(16);
            let stdin_tx = tx.clone();
            let stdin_reader = std::thread::spawn(move || {
                use std::io::BufRead;
                let stdin = std::io::stdin();
                for line in stdin.lock().lines() {
                    match line {
                        Ok(text) => {
                            if stdin_tx.blocking_send(Some(text)).is_err() {
                                break;
                            }
                        }
                        Err(_) => break,
                    }
                }
                let _ = stdin_tx.blocking_send(None);
            });

            loop {
                let context = neonet::shell::Context::Local;
                let cwd = "/";
                print!("{}", neonet::shell::prompt(clock, &context, cwd));
                use std::io::Write;
                let _ = io::stdout().flush();

                tokio::select! {
                    signal = tokio::signal::ctrl_c() => {
                        if signal.is_ok() {
                            println!();
                            println!("KeyboardInterrupt — use 'quit' to exit.");
                        }
                    }
                    line = rx.recv() => {
                        let Some(Some(line)) = line else { break };
                        history.push(&line);
                        let words = neonet::shell::tokenize(&line);
                        if words.is_empty() {
                            continue;
                        }
                        let command = words[0].to_ascii_lowercase();
                        let args = &words[1..];

                        let mut quit = false;
                        match command.as_str() {
                            "help" => {
                                println!("{}{}{}", neonet::shell::CYAN, neonet::shell::logo(), neonet::shell::RESET);
                                println!("{BOLD}System{RESET}
  echo TEXT                print text
  clock                    toggle time in the prompt
  history                  last commands
  sysinfo                  host OS / RAM / battery
  whoami                   this device's identity
  devices                  known mesh devices
  update [--repo R] [--branch B] [--release]   pull + rebuild (manual, fast-forward only)
  help                     this list
  clear                    clear the screen
  reboot                   restart the shell
  quit | exit              leave the shell
{RESET}{BOLD}Tools & mesh{RESET}
  nsh ALIAS [CMD...]       SSH redirector passthrough
  connect ALIAS            same, interactive session via your ssh binary
  browse ALIAS [PATH]      list a peer's shared directory (one-shot)
  fork ALIAS PATH          pull a full local copy into NEONET_HOME/forked/ (one-shot)
  send ALIAS FILE          send a file to any device (resumable)
  channel ALIAS MSG        private 1:1 message, or show log with that peer
  transfers                inbound file transfers and resume state
  store push ALIAS FILE    encrypt + store chunks on a device (prints a file id)
  store pull ALIAS ID [OUT]    fetch, decrypt, reconstruct
  replicate SRC DST ID     copy a stored file between two cores (opaque to both)
{RESET}{BOLD}Services & pairing{RESET}
  register ALIAS ADDR [TTL]    publish your address at a rendezvous node
  scan ALIAS [FILTER] [--active]   list registered devices
  pair [TTL]               issue a single-use pairing token (this shell accepts)
  flash ALIAS TOKEN        redeem an acceptor's pairing token
  pairs [--as-allow]       show the pairing ledger (or emit an allow-list)
  revoke DEVICE HEX        broadcast a signed revocation to a core
  operator add HEX | operator list    manage this node's operator set
{RESET}{BOLD}Lobby & messaging{RESET}
  host LOBBY [--title T] [--welcome W] [--max-members N]   become the host
  join LOBBY HOST_KEY_ALIAS LOBBY_KEY     join a lobby (relays arrive live here)
  say TEXT                 post to the most recently joined lobby
  post LOBBY TEXT          post to a specific lobby
  lobby log [NAME]         show received posts
  lobby members [NAME]     ask the host who is in
  lobby leave [NAME]       leave a lobby
{RESET}{BOLD}Daemons{RESET}
  core --listen ADDR [--allow-file FILE]   launch a relay core in background
  serve --listen ADDR [--allow-file FILE]  alias of core
  edge --bootstrap FILE    launch an edge daemon in background
  daemons                  list background daemons
  stop PID                 stop a background daemon
{RESET}");
                            }
                            "clear" => {
                                print!("\x1b[2J\x1b[H");
                                use std::io::Write;
                                let _ = io::stdout().flush();
                            }
                            "clock" => {
                                clock = !clock;
                                println!(
                                    "prompt time {}",
                                    if clock { "on" } else { "off" }
                                );
                            }
                            "echo" => println!("{}", args.join(" ")),
                            "history" => {
                                for entry in &history.entries {
                                    println!("{entry}");
                                }
                            }
                            "sysinfo" => {
                                for row in neonet::shell::system_info() {
                                    println!("{row}");
                                }
                            }
                            "whoami" => {
                                println!("NeoNet {SOFTWARE_VERSION}");
                                println!(
                                    "identity fingerprint: {}",
                                    local_identity.public().fingerprint()
                                );
                                println!(
                                    "public key: {}",
                                    hex::encode(local_identity.public().public_key)
                                );
                                println!("identity key: {}", local_identity.path().display());
                            }
                            "devices" => {
                                let directory = match load_devices(&root) {
                                    Ok(d) => d,
                                    Err(err) => {
                                        println!("{}{:#}{}", neonet::shell::RED, err, neonet::shell::RESET);
                                        continue;
                                    }
                                };
                                let devices = ssh::devices(&directory);
                                if devices.is_empty() {
                                    println!("No devices configured. Add entries to {}/devices.json — see docs/CLI.md#devices.", root.display());
                                } else {
                                    for (alias, fingerprint) in devices {
                                        println!("{alias}\t{fingerprint}");
                                    }
                                }
                            }
                            "quit" | "exit" => {
                                quit = true;
                            }
                            "reboot" => {
                                println!("Rebooting shell...");
                                neonet::shell::boot();
                                neonet::shell::home(None);
                            }
                            // ---- mesh ----
                            "channel" => {
                                // channel ALIAS MSG   send to that device
                                // channel ALIAS       show the received log with that peer
                                let Some(alias) = args.first().cloned() else {
                                    println!("usage: channel ALIAS [MSG]  (MSG omitted — show the log with that peer)");
                                    continue;
                                };
                                let known = load_devices(&root)
                                    .map(|directory| directory.resolve(&alias).is_some())
                                    .unwrap_or(false);
                                if !known {
                                    println!(
                                        "{}'{alias}' is not a known device — see 'devices'.{}",
                                        neonet::shell::RED,
                                        neonet::shell::RESET
                                    );
                                    continue;
                                }
                                let text = if args.len() > 1 {
                                    Some(args[1..].join(" "))
                                } else {
                                    None
                                };
                                match session.peer(&root, &alias).await {
                                    Ok(peer) => match text {
                                        None => {
                                            let lines = neonet::lobby::read_channel(
                                                &root,
                                                &peer.fingerprint(),
                                            );
                                            if lines.is_empty() {
                                                println!(
                                                    "no channel messages with {} yet.",
                                                    peer.fingerprint()
                                                );
                                            } else {
                                                for line in lines {
                                                    println!(
                                                        "{}\t{}\t{}",
                                                        line.at, line.sender, line.text
                                                    );
                                                }
                                            }
                                        }
                                        Some(text) => {
                                            let reply = session
                                                .call(
                                                    &root,
                                                    &alias,
                                                    neonet::app::AppFrame::Channel(
                                                        neonet::app::lobby::ChannelFrame::Send {
                                                            text: text.clone(),
                                                        },
                                                    ),
                                                )
                                                .await;
                                            match reply {
                                                Ok(reply) => match neonet::app::AppFrame::decode(
                                                    &reply.payload,
                                                ) {
                                                    neonet::app::AppFrame::Channel(
                                                        neonet::app::lobby::ChannelFrame::Ack { at },
                                                    ) => {
                                                        println!(
                                                            "{}channel message {} acked at {at}{}",
                                                            neonet::shell::GREEN,
                                                            text,
                                                            neonet::shell::RESET
                                                        );
                                                    }
                                                    other => println!(
                                                        "{}unexpected reply: {other:?}{}",
                                                        neonet::shell::RED,
                                                        neonet::shell::RESET
                                                    ),
                                                },
                                                Err(err) => println!(
                                                    "{}{}{}",
                                                    neonet::shell::RED,
                                                    err,
                                                    neonet::shell::RESET
                                                ),
                                            }
                                        }
                                    },
                                    Err(err) => println!(
                                        "{}{}{}",
                                        neonet::shell::RED,
                                        err,
                                        neonet::shell::RESET
                                    ),
                                }
                            }
                            "nsh" => {
                                let alias = args.first().map(String::as_str).unwrap_or("");
                                if alias.is_empty() {
                                    println!("usage: nsh ALIAS [CMD...]");
                                } else {
                                    let directory = match load_devices(&root) {
                                        Ok(d) => d,
                                        Err(err) => {
                                            println!("{}{:#}{}", neonet::shell::RED, err, neonet::shell::RESET);
                                            continue;
                                        }
                                    };
                                    match ssh::connect(&directory, alias, &args[1..]) {
                                        Ok(_) => {}
                                        Err(err) => println!("{}{}{}", neonet::shell::RED, err, neonet::shell::RESET),
                                    }
                                }
                            }
                            "connect" => {
                                let alias = args.first().map(String::as_str).unwrap_or("");
                                if alias.is_empty() {
                                    println!("usage: connect ALIAS  (hand off to your ssh binary)");
                                } else {
                                    let directory = match load_devices(&root) {
                                        Ok(d) => d,
                                        Err(err) => {
                                            println!("{}{:#}{}", neonet::shell::RED, err, neonet::shell::RESET);
                                            continue;
                                        }
                                    };
                                    let no_command: Vec<String> = Vec::new();
                                    match ssh::connect(&directory, alias, &no_command) {
                                        Ok(_) => {}
                                        Err(err) => println!("{}{}{}", neonet::shell::RED, err, neonet::shell::RESET),
                                    }
                                }
                            }

                            // ---- one-shot files & transfers (no mount needed) ----
                            "browse" => {
                                let device_id = args.first().map(String::as_str).unwrap_or("");
                                let path = args.get(1).cloned().unwrap_or_else(|| ".".to_string());
                                if device_id.is_empty() {
                                    println!("usage: browse ALIAS [PATH]");
                                } else {
                                    let reply = session
                                        .call(
                                            &root,
                                            device_id,
                                            neonet::app::AppFrame::Burrow(
                                                neonet::app::burrow::BurrowFrame::List { path },
                                            ),
                                        )
                                        .await;
                                    match reply {
                                        Ok(reply) => match neonet::app::AppFrame::decode(&reply.payload) {
                                            neonet::app::AppFrame::Burrow(
                                                neonet::app::burrow::BurrowFrame::Listing { entries, .. },
                                            ) => {
                                                if entries.is_empty() {
                                                    println!("(empty)");
                                                }
                                                for entry in entries {
                                                    let suffix = match entry.kind {
                                                        neonet::burrow::EntryKind::File => "",
                                                        neonet::burrow::EntryKind::Directory => "/",
                                                        neonet::burrow::EntryKind::Symlink => "@",
                                                    };
                                                    println!("{}{}\t{}", entry.name, suffix, entry.size);
                                                }
                                            }
                                            neonet::app::AppFrame::Burrow(
                                                neonet::app::burrow::BurrowFrame::Error { message, .. },
                                            ) => println!(
                                                "{}{}{}",
                                                neonet::shell::RED,
                                                format_args!("browse failed on the host: {message}"),
                                                neonet::shell::RESET
                                            ),
                                            other => println!(
                                                "{}{:?}{}",
                                                neonet::shell::RED,
                                                other,
                                                neonet::shell::RESET
                                            ),
                                        },
                                        Err(err) => println!("{}{}{}", neonet::shell::RED, err, neonet::shell::RESET),
                                    }
                                }
                            }
                            "fork" => {
                                let device_id = args.first().map(String::as_str).unwrap_or("");
                                let path = args.get(1).cloned().unwrap_or_default();
                                if device_id.is_empty() || path.is_empty() {
                                    println!("usage: fork ALIAS PATH  (one-shot)");
                                } else {
                                    let reply = session
                                        .call(
                                            &root,
                                            device_id,
                                            neonet::app::AppFrame::Burrow(
                                                neonet::app::burrow::BurrowFrame::Read { path: path.clone() },
                                            ),
                                        )
                                        .await;
                                    match reply {
                                        Ok(reply) => match neonet::app::AppFrame::decode(&reply.payload) {
                                            neonet::app::AppFrame::Burrow(
                                                neonet::app::burrow::BurrowFrame::Content { bytes, .. },
                                            ) => {
                                                let destination = root.join("forked").join(&path);
                                                if let Err(err) = (|| -> io::Result<()> {
                                                    if let Some(parent) = destination.parent() {
                                                        fs::create_dir_all(parent)?;
                                                    }
                                                    fs::write(&destination, bytes)?;
                                                    Ok(())
                                                })() {
                                                    println!("{}{}{}", neonet::shell::RED, err, neonet::shell::RESET);
                                                } else {
                                                    println!("forked {path} to {}", destination.display());
                                                }
                                            }
                                            neonet::app::AppFrame::Burrow(
                                                neonet::app::burrow::BurrowFrame::Error { message, .. },
                                            ) => println!(
                                                "{}{}{}",
                                                neonet::shell::RED,
                                                format_args!("fork failed on the host: {message}"),
                                                neonet::shell::RESET
                                            ),
                                            other => println!(
                                                "{}{:?}{}",
                                                neonet::shell::RED,
                                                other,
                                                neonet::shell::RESET
                                            ),
                                        },
                                        Err(err) => println!("{}{}{}", neonet::shell::RED, err, neonet::shell::RESET),
                                    }
                                }
                            }
                            "send" => {
                                let device_id = args.first().map(String::as_str).unwrap_or("");
                                let file = args.get(1).map(String::as_str).unwrap_or("");
                                if device_id.is_empty() || file.is_empty() {
                                    println!("usage: send ALIAS FILE  (resumable)");
                                } else {
                                    let file_path = PathBuf::from(file);
                                    if !file_path.exists() {
                                        println!("no such local file: {file}");
                                        continue;
                                    }
                                    let peer = match session.peer(&root, device_id).await {
                                        Ok(peer) => peer,
                                        Err(err) => {
                                            println!("{}{}{}", neonet::shell::RED, err, neonet::shell::RESET);
                                            continue;
                                        }
                                    };
                                    match neonet::app::files::send_file_and_wait(
                                        &peer,
                                        &mut session.client,
                                        file_path,
                                        std::time::Duration::from_secs(120),
                                    )
                                    .await
                                    {
                                        Ok(state) if state.complete() => {
                                            println!(
                                                "{}sent {file} to {device_id}: {} of {} chunks verified{}",
                                                neonet::shell::GREEN,
                                                state.verified_chunks.len(),
                                                state.manifest.chunks.len(),
                                                neonet::shell::RESET
                                            );
                                        }
                                        Ok(state) if state.lost_chunks.is_empty() => {
                                            println!(
                                                "partially sent {file} to {device_id}: {} of {} chunks verified \
                                                 (run 'send {device_id} {file}' again to resume)",
                                                state.verified_chunks.len(),
                                                state.manifest.chunks.len(),
                                            );
                                        }
                                        Ok(_state) => println!(
                                            "{}{}{}",
                                            neonet::shell::RED,
                                            format_args!("failed to send {file} to {device_id}: some chunks were lost"),
                                            neonet::shell::RESET
                                        ),
                                        Err(err) => println!("{}{}{}", neonet::shell::RED, err, neonet::shell::RESET),
                                    }
                                }
                            }
                            "transfers" => {
                                match neonet::files::list_transfers(&root) {
                                    Ok(transfers) => {
                                        if transfers.is_empty() {
                                            println!("No inbound transfers recorded on this device yet.");
                                        } else {
                                            for transfer in transfers {
                                                let status = if transfer.verified == transfer.total {
                                                    "complete"
                                                } else {
                                                    "incomplete"
                                                };
                                                println!(
                                                    "{}\t{}\t{}/{}\t{} lost\t{}",
                                                    transfer.id,
                                                    transfer.name,
                                                    transfer.verified,
                                                    transfer.total,
                                                    transfer.lost,
                                                    status,
                                                );
                                            }
                                        }
                                    }
                                    Err(err) => println!("{}{}{}", neonet::shell::RED, err, neonet::shell::RESET),
                                }
                            }
                            "store" => {
                                let subcommand = args.first().map(String::as_str).unwrap_or("");
                                match subcommand {
                                    "push" => {
                                        let device_id = args.get(1).map(String::as_str).unwrap_or("");
                                        let file = args.get(2).map(String::as_str).unwrap_or("");
                                        if device_id.is_empty() || file.is_empty() {
                                            println!("usage: store push ALIAS FILE");
                                            continue;
                                        }
                                        let file_path = PathBuf::from(file);
                                        if !file_path.exists() {
                                            println!("no such local file: {file}");
                                            continue;
                                        }
                                        let peer = match session.peer(&root, device_id).await {
                                            Ok(peer) => peer,
                                            Err(err) => {
                                                println!("{}{}{}", neonet::shell::RED, err, neonet::shell::RESET);
                                                continue;
                                            }
                                        };
                                        let (manifest, chunks) = match neonet::files::build_manifest(
                                            &file_path,
                                            session.node().local(),
                                            neonet::files::DEFAULT_CHUNK_SIZE,
                                        ) {
                                            Ok(built) => built,
                                            Err(err) => {
                                                println!("{}{}{}", neonet::shell::RED, err, neonet::shell::RESET);
                                                continue;
                                            }
                                        };
                                        let file_id = neonet::files::manifest_id(&manifest);
                                        let key = match neonet::storage::LocalKeyStore::new(root.join("storage.key"))
                                            .load_or_generate()
                                        {
                                            Ok(key) => key,
                                            Err(err) => {
                                                println!("{}{}{}", neonet::shell::RED, err, neonet::shell::RESET);
                                                continue;
                                            }
                                        };
                                        let encrypted = match chunks
                                            .iter()
                                            .map(|chunk| neonet::storage::encrypt_chunk(&key, chunk))
                                            .collect::<Result<Vec<_>, _>>()
                                        {
                                            Ok(encrypted) => encrypted,
                                            Err(err) => {
                                                println!("{}{}{}", neonet::shell::RED, err, neonet::shell::RESET);
                                                continue;
                                            }
                                        };
                                        match neonet::app::storage::push_chunks(
                                            &peer,
                                            &mut session.client,
                                            &file_id,
                                            &manifest,
                                            &encrypted,
                                        )
                                        .await
                                        {
                                            Ok(()) => println!(
                                                "stored {file} on {device_id} (file id {file_id})"
                                            ),
                                            Err(err) => println!(
                                                "{}{}{}",
                                                neonet::shell::RED,
                                                format_args!("could not store {file} on {device_id}: {err}"),
                                                neonet::shell::RESET
                                            ),
                                        }
                                    }
                                    "pull" => {
                                        let device_id = args.get(1).map(String::as_str).unwrap_or("");
                                        let file_id = args.get(2).map(String::as_str).unwrap_or("");
                                        let output = args.get(3).map(PathBuf::from);
                                        if device_id.is_empty() || file_id.is_empty() {
                                            println!("usage: store pull ALIAS FILEID [OUTPUT]");
                                            continue;
                                        }
                                        let peer = match session.peer(&root, device_id).await {
                                            Ok(peer) => peer,
                                            Err(err) => {
                                                println!("{}{}{}", neonet::shell::RED, err, neonet::shell::RESET);
                                                continue;
                                            }
                                        };
                                        let (manifest, chunks) = match neonet::app::storage::pull_chunks(
                                            &peer,
                                            &mut session.client,
                                            file_id,
                                        )
                                        .await
                                        {
                                            Ok(pulled) => pulled,
                                            Err(err) => {
                                                println!("{}{}{}", neonet::shell::RED, err, neonet::shell::RESET);
                                                continue;
                                            }
                                        };
                                        let key = match neonet::storage::LocalKeyStore::new(root.join("storage.key"))
                                            .load_or_generate()
                                        {
                                            Ok(key) => key,
                                            Err(err) => {
                                                println!("{}{}{}", neonet::shell::RED, err, neonet::shell::RESET);
                                                continue;
                                            }
                                        };
                                        let plaintext = match chunks
                                            .iter()
                                            .map(|encrypted| neonet::storage::decrypt_chunk(&key, encrypted))
                                            .collect::<Result<Vec<_>, _>>()
                                        {
                                            Ok(plaintext) => plaintext,
                                            Err(err) => {
                                                println!("{}{}{}", neonet::shell::RED, err, neonet::shell::RESET);
                                                continue;
                                            }
                                        };
                                        let destination =
                                            output.unwrap_or_else(|| PathBuf::from(&manifest.name));
                                        match neonet::files::reconstruct(
                                            &manifest,
                                            &plaintext,
                                            &destination,
                                        ) {
                                            Ok(()) => println!(
                                                "restored {file_id} from {device_id} to {}",
                                                destination.display()
                                            ),
                                            Err(err) => println!(
                                                "{}{}{}",
                                                neonet::shell::RED,
                                                err,
                                                neonet::shell::RESET
                                            ),
                                        }
                                    }
                                    _ => println!(
                                        "usage: store push ALIAS FILE    |    store pull ALIAS FILEID [OUTPUT]"
                                    ),
                                }
                            }
                            "replicate" => {
                                let src = args.first().map(String::as_str).unwrap_or("");
                                let dst = args.get(1).map(String::as_str).unwrap_or("");
                                let file_id = args.get(2).map(String::as_str).unwrap_or("");
                                if src.is_empty() || dst.is_empty() || file_id.is_empty() {
                                    println!("usage: replicate SRC DST FILEID  (copy a stored file between cores)");
                                    continue;
                                }
                                let directory = match load_devices(&root) {
                                    Ok(directory) => directory,
                                    Err(err) => {
                                        println!("{}{}{}", neonet::shell::RED, err, neonet::shell::RESET);
                                        continue;
                                    }
                                };
                                let Some(dst_identity) = directory.resolve(dst).map(|record| record.identity.clone()) else {
                                    println!(
                                        "{}{}{}",
                                        neonet::shell::RED,
                                        format_args!("device '{dst}' not found in devices.json"),
                                        neonet::shell::RESET
                                    );
                                    continue;
                                };
                                let src_identity = match session.peer(&root, src).await {
                                    Ok(peer) => peer,
                                    Err(err) => {
                                        println!("{}{}{}", neonet::shell::RED, err, neonet::shell::RESET);
                                        continue;
                                    }
                                };
                                let (manifest, chunks) = match neonet::app::storage::pull_chunks(
                                    &src_identity,
                                    &mut session.client,
                                    file_id,
                                )
                                .await
                                {
                                    Ok(pulled) => pulled,
                                    Err(err) => {
                                        println!("{}{}{}", neonet::shell::RED, err, neonet::shell::RESET);
                                        continue;
                                    }
                                };
                                match neonet::app::storage::push_chunks(
                                    &dst_identity,
                                    &mut session.client,
                                    file_id,
                                    &manifest,
                                    &chunks,
                                )
                                .await
                                {
                                    Ok(()) => println!(
                                        "replicated {file_id} ({} chunks) from {src} to {dst}",
                                        chunks.len()
                                    ),
                                    Err(err) => println!(
                                        "{}{}{}",
                                        neonet::shell::RED,
                                        err,
                                        neonet::shell::RESET
                                    ),
                                }
                            }

                            // ---- services: rendezvous, pairing, operators ----
                            "register" => {
                                let device_id = args.first().map(String::as_str).unwrap_or("");
                                let addr = args.get(1).map(String::as_str).unwrap_or("");
                                if device_id.is_empty() || addr.is_empty() {
                                    println!("usage: register RENDEZVOUS_ALIAS ADDR [TTL_SECS]  (e.g. register ops 192.0.2.10:7000 3600)");
                                    continue;
                                }
                                if !addr.contains(':') {
                                    println!("{}ADDR must be a host:port peers can dial back, e.g. 192.0.2.10:7000{}", neonet::shell::RED, neonet::shell::RESET);
                                    continue;
                                }
                                let ttl = args.get(2).and_then(|value| value.parse::<u32>().ok());
                                let frame = match ttl {
                                    Some(ttl) => neonet::app::rendezvous::register_frame_with_ttl(
                                        session.node(),
                                        addr.to_string(),
                                        ttl,
                                    ),
                                    None => neonet::app::rendezvous::register_frame(
                                        session.node(),
                                        addr.to_string(),
                                    ),
                                };
                                let reply = session
                                    .call(&root, device_id, neonet::app::AppFrame::Rendezvous(frame))
                                    .await;
                                match reply {
                                    Ok(reply) => match neonet::app::AppFrame::decode(&reply.payload) {
                                        neonet::app::AppFrame::Rendezvous(
                                            neonet::app::rendezvous::RendezvousFrame::Registered,
                                        ) => println!("registered {addr} with {device_id}"),
                                        neonet::app::AppFrame::Rendezvous(
                                            neonet::app::rendezvous::RendezvousFrame::Error { message },
                                        ) => println!(
                                            "{}{}{}",
                                            neonet::shell::RED,
                                            format_args!("{device_id} refused the registration: {message}"),
                                            neonet::shell::RESET
                                        ),
                                        other => println!(
                                            "{}{:?}{}",
                                            neonet::shell::RED,
                                            other,
                                            neonet::shell::RESET
                                        ),
                                    },
                                    Err(err) => println!("{}{}{}", neonet::shell::RED, err, neonet::shell::RESET),
                                }
                            }
                            "scan" => {
                                let device_id = args.first().map(String::as_str).unwrap_or("");
                                let filter = args.get(1).cloned();
                                let active = args.iter().any(|arg| arg == "--active");
                                if device_id.is_empty() {
                                    println!("usage: scan RENDEZVOUS_ALIAS [FILTER] [--active]");
                                    continue;
                                }
                                let reply = session
                                    .call(
                                        &root,
                                        device_id,
                                        neonet::app::AppFrame::Rendezvous(
                                            neonet::app::rendezvous::RendezvousFrame::List,
                                        ),
                                    )
                                    .await;
                                let records = match reply {
                                    Ok(reply) => match neonet::app::AppFrame::decode(&reply.payload) {
                                        neonet::app::AppFrame::Rendezvous(
                                            neonet::app::rendezvous::RendezvousFrame::ListResult { records },
                                        ) => records,
                                        neonet::app::AppFrame::Rendezvous(
                                            neonet::app::rendezvous::RendezvousFrame::Error { message },
                                        ) => {
                                            println!(
                                                "{}{}{}",
                                                neonet::shell::RED,
                                                format_args!("{device_id} could not enumerate: {message}"),
                                                neonet::shell::RESET
                                            );
                                            continue;
                                        }
                                        other => {
                                            println!("{}{:?}{}", neonet::shell::RED, other, neonet::shell::RESET);
                                            continue;
                                        }
                                    },
                                    Err(err) => {
                                        println!("{}{}{}", neonet::shell::RED, err, neonet::shell::RESET);
                                        continue;
                                    }
                                };
                                let filter = filter.unwrap_or_default().to_lowercase();
                                let mut hits: Vec<_> = records
                                    .iter()
                                    .filter(|record| {
                                        let fingerprint =
                                            record.identity.fingerprint().to_lowercase();
                                        filter.is_empty()
                                            || fingerprint.contains(&filter)
                                            || record.address.to_lowercase().contains(&filter)
                                    })
                                    .collect();
                                hits.sort_by_key(|record| record.identity.fingerprint());
                                if active {
                                    let mut live: Vec<&neonet::app::rendezvous::EndpointRecord> =
                                        Vec::new();
                                    for record in &hits {
                                        let probe = session
                                            .call(
                                                &root,
                                                device_id,
                                                neonet::app::AppFrame::Rendezvous(
                                                    neonet::app::rendezvous::RendezvousFrame::Probe {
                                                        fingerprint: record.identity.fingerprint(),
                                                    },
                                                ),
                                            )
                                            .await;
                                        if let Ok(probe) = probe {
                                            if let neonet::app::AppFrame::Rendezvous(
                                                neonet::app::rendezvous::RendezvousFrame::ProbeResult { alive, .. },
                                            ) = neonet::app::AppFrame::decode(&probe.payload)
                                            {
                                                if alive {
                                                    live.push(record);
                                                } else {
                                                    println!(
                                                        "{} @ {} (stale)",
                                                        record.identity.fingerprint(),
                                                        record.address
                                                    );
                                                }
                                            }
                                        }
                                    }
                                    hits = live;
                                }
                                if hits.is_empty() {
                                    println!(
                                        "(no devices registered{})",
                                        if filter.is_empty() {
                                            String::new()
                                        } else {
                                            format!(" matching '{filter}'")
                                        }
                                    );
                                }
                                for record in &hits {
                                    println!("{} @ {}", record.identity.fingerprint(), record.address);
                                }
                            }
                            "flash" => {
                                let device_id = args.first().map(String::as_str).unwrap_or("");
                                let token = args.get(1).map(String::as_str).unwrap_or("");
                                if device_id.is_empty() || token.is_empty() {
                                    println!("usage: flash ACCEPTOR_ALIAS TOKEN");
                                    continue;
                                }
                                let reply = session
                                    .call(
                                        &root,
                                        device_id,
                                        neonet::app::AppFrame::Pair(
                                            neonet::app::pair::PairFrame::Redeem {
                                                token: token.to_string(),
                                            },
                                        ),
                                    )
                                    .await;
                                match reply {
                                    Ok(reply) => match neonet::app::AppFrame::decode(&reply.payload) {
                                        neonet::app::AppFrame::Pair(
                                            neonet::app::pair::PairFrame::Redeemed { fingerprint },
                                        ) => println!("{device_id} paired {fingerprint}"),
                                        neonet::app::AppFrame::Pair(
                                            neonet::app::pair::PairFrame::Error { message },
                                        ) => println!(
                                            "{}{}{}",
                                            neonet::shell::RED,
                                            format_args!("{device_id} refused the token: {message}"),
                                            neonet::shell::RESET
                                        ),
                                        other => println!(
                                            "{}{:?}{}",
                                            neonet::shell::RED,
                                            other,
                                            neonet::shell::RESET
                                        ),
                                    },
                                    Err(err) => println!("{}{}{}", neonet::shell::RED, err, neonet::shell::RESET),
                                }
                            }
                            "pairs" => {
                                if args.iter().any(|arg| arg == "--as-allow") {
                                    let keys = neonet::pair::paired_devices(&root)
                                        .iter()
                                        .map(|record| hex::encode(record.public_key))
                                        .collect::<Vec<String>>();
                                    match serde_json::to_string_pretty(&keys) {
                                        Ok(json) => println!("{json}"),
                                        Err(err) => println!("{}{}{}", neonet::shell::RED, err, neonet::shell::RESET),
                                    }
                                } else {
                                    let paired = neonet::pair::paired_devices(&root);
                                    if paired.is_empty() {
                                        println!(
                                            "no pairings recorded yet — 'pair' issues a token, a peer redeems it with 'flash'."
                                        );
                                    } else {
                                        for record in paired {
                                            println!(
                                                "{}\t{}\t{}",
                                                record.fingerprint,
                                                hex::encode(record.public_key),
                                                record.paired_at
                                            );
                                        }
                                    }
                                }
                            }
                            "pair" => {
                                let ttl = args
                                    .iter()
                                    .position(|arg| arg == "--ttl")
                                    .and_then(|index| args.get(index + 1))
                                    .and_then(|value| value.parse::<u64>().ok())
                                    .or_else(|| args.first().and_then(|value| value.parse::<u64>().ok()));
                                match neonet::pair::issue_token(&root, ttl) {
                                    Ok(token) => {
                                        println!(
                                            "pairing token: {token}  (single use; {}s)",
                                            ttl.unwrap_or(120)
                                        );
                                        println!(
                                            "   this shell is the acceptor — a peer redeems the token with \
                                             'flash <this-device-alias> {token}' while the shell stays open."
                                        );
                                    }
                                    Err(err) => println!("{}{}{}", neonet::shell::RED, err, neonet::shell::RESET),
                                }
                            }
                            "revoke" => {
                                let device_id = args.first().map(String::as_str).unwrap_or("");
                                let revoked = args.get(1).map(String::as_str).unwrap_or("");
                                if device_id.is_empty() || revoked.is_empty() {
                                    println!("usage: revoke DEVICE HEX_PUBLIC_KEY  (the core applies it only if you are in its operator set)");
                                    continue;
                                }
                                let revoked_identity = match parse_public_key(revoked)
                                    .map(|public_key| PublicIdentity { public_key })
                                {
                                    Ok(identity) => identity,
                                    Err(err) => {
                                        println!("{}{}{}", neonet::shell::RED, err, neonet::shell::RESET);
                                        continue;
                                    }
                                };
                                let epoch = match next_revocation_epoch(&root) {
                                    Ok(epoch) => epoch,
                                    Err(err) => {
                                        println!("{}{}{}", neonet::shell::RED, err, neonet::shell::RESET);
                                        continue;
                                    }
                                };
                                let payload = neonet::app::core::revoke_payload(epoch, &revoked_identity);
                                let signature = reload_identity(&root).sign(&payload);
                                let reply = session
                                    .call(
                                        &root,
                                        device_id,
                                        neonet::app::AppFrame::Core(
                                            neonet::app::core::CoreFrame::RevokeBroadcast {
                                                revoked: revoked_identity,
                                                epoch,
                                                signature,
                                            },
                                        ),
                                    )
                                    .await;
                                match reply {
                                    Ok(reply) => match neonet::app::AppFrame::decode(&reply.payload) {
                                        neonet::app::AppFrame::Core(
                                            neonet::app::core::CoreFrame::RevokeAck { epoch },
                                        ) => println!("{device_id} acknowledged revocation epoch {epoch}"),
                                        neonet::app::AppFrame::Core(
                                            neonet::app::core::CoreFrame::RevokeRefuse { epoch, reason },
                                        ) => println!(
                                            "{}{}{}",
                                            neonet::shell::RED,
                                            format_args!("{device_id} refused revocation epoch {epoch}: {reason}"),
                                            neonet::shell::RESET
                                        ),
                                        other => println!(
                                            "{}{:?}{}",
                                            neonet::shell::RED,
                                            other,
                                            neonet::shell::RESET
                                        ),
                                    },
                                    Err(err) => println!("{}{}{}", neonet::shell::RED, err, neonet::shell::RESET),
                                }
                            }
                            "operator" => {
                                let subcommand = args.first().map(String::as_str).unwrap_or("");
                                match subcommand {
                                    "add" => {
                                        let hex_key = args.get(1).map(String::as_str).unwrap_or("");
                                        if hex_key.is_empty() {
                                            println!("usage: operator add HEX_PUBLIC_KEY");
                                            continue;
                                        }
                                        let identity = match parse_public_key(hex_key)
                                            .map(|public_key| PublicIdentity { public_key })
                                        {
                                            Ok(identity) => identity,
                                            Err(err) => {
                                                println!("{}{}{}", neonet::shell::RED, err, neonet::shell::RESET);
                                                continue;
                                            }
                                        };
                                        let node = match Node::new(reload_identity(&root), 16) {
                                        Ok(node) => node,
                                        Err(err) => {
                                            println!("{}{}{}", neonet::shell::RED, err, neonet::shell::RESET);
                                            continue;
                                        }
                                    };
                                    match neonet::app::core::set_operator(&node, &identity) {
                                            Ok(()) => println!(
                                                "added {} to the operator set at {} (this node only)",
                                                identity.fingerprint(),
                                                root.join("operators.json").display()
                                            ),
                                            Err(err) => println!("{}{}{}", neonet::shell::RED, err, neonet::shell::RESET),
                                        }
                                    }
                                    "list" => {
                                        let node = match Node::new(reload_identity(&root), 16) {
                                            Ok(node) => node,
                                            Err(err) => {
                                                println!("{}{}{}", neonet::shell::RED, err, neonet::shell::RESET);
                                                continue;
                                            }
                                        };
                                        let operators = neonet::app::core::operators(&node);
                                        if operators.is_empty() {
                                            println!(
                                                "operator set is empty — no one can revoke through this node (fail closed). \
                                                 Add a key with 'operator add HEX'."
                                            );
                                        } else {
                                            for fingerprint in operators {
                                                println!("{fingerprint}");
                                            }
                                        }
                                    }
                                    _ => println!("usage: operator add HEX_PUBLIC_KEY | operator list"),
                                }
                            }

                            // ---- lobbies & messaging ----
                            "host" => {
                                let name = args.first().map(String::as_str).unwrap_or("");
                                if name.is_empty() {
                                    println!("usage: host LOBBY [--title T] [--welcome W] [--max-members N]");
                                } else {
                                    let title = flag_value(args, "--title");
                                    let welcome = flag_value(args, "--welcome");
                                    let max_members = flag_usize(args, "--max-members");
                                    let key_hex = hex::encode(neonet::lobby::new_key());
                                    neonet::app::lobby::register_host(
                                        session.node().home(),
                                        name,
                                        &key_hex,
                                        neonet::app::lobby::LobbyOptions {
                                            title: title.clone().unwrap_or_default(),
                                            welcome: welcome.clone().unwrap_or_default(),
                                            max_members,
                                        },
                                    );
                                    println!(
                                        "hosting lobby '{name}' ({}) — this shell is the host, members relay \
                                         through your device while the shell stays open.",
                                        title.as_deref().unwrap_or(name)
                                    );
                                    if let Some(welcome) = &welcome {
                                        println!("welcome message: {welcome}");
                                    }
                                    if let Some(cap) = max_members {
                                        println!("seat cap: {cap} members (the host does not count)");
                                    }
                                    println!("  lobby key: {key_hex}");
                                    println!(
                                        "members join with: join {name} <this-device-alias> {key_hex}"
                                    );
                                }
                            }
                            "join" => {
                                let lobby_name = args.first().map(String::as_str).unwrap_or("");
                                let host_device_id = args.get(1).map(String::as_str).unwrap_or("");
                                let key = args.get(2).map(String::as_str).unwrap_or("");
                                if lobby_name.is_empty() || host_device_id.is_empty() || key.is_empty() {
                                    println!("usage: join LOBBY HOST_KEY_ALIAS LOBBY_KEY");
                                    continue;
                                }
                                let host_peer = match session.peer(&root, host_device_id).await {
                                    Ok(peer) => peer,
                                    Err(err) => {
                                        println!("{}{}{}", neonet::shell::RED, err, neonet::shell::RESET);
                                        continue;
                                    }
                                };
                                let reply = match session
                                    .client
                                    .call(
                                        &host_peer,
                                        neonet::app::AppFrame::Lobby(
                                            neonet::app::lobby::LobbyFrame::Join {
                                                lobby_name: lobby_name.to_string(),
                                                key: key.to_string(),
                                            },
                                        ),
                                    )
                                    .await
                                {
                                    Ok(reply) => reply,
                                    Err(err) => {
                                        println!("{}{}{}", neonet::shell::RED, err, neonet::shell::RESET);
                                        continue;
                                    }
                                };
                                match neonet::app::AppFrame::decode(&reply.payload) {
                                    neonet::app::AppFrame::Lobby(
                                        neonet::app::lobby::LobbyFrame::Joined {
                                            lobby_name,
                                            title,
                                            welcome,
                                        },
                                    ) => {
                                        if let Err(err) = neonet::lobby::add_to_roster(
                                            &root,
                                            neonet::lobby::MemberLobby {
                                                name: lobby_name.clone(),
                                                host_alias: host_device_id.to_string(),
                                                host_fingerprint: host_peer.fingerprint(),
                                                key_hex: key.to_string(),
                                                title: title.clone(),
                                                welcome: welcome.clone(),
                                            },
                                        ) {
                                            println!("{}{}{}", neonet::shell::RED, err, neonet::shell::RESET);
                                        }
                                        println!(
                                            "joined lobby '{lobby_name}' ({})",
                                            if title.is_empty() { &lobby_name } else { &title }
                                        );
                                        if !title.is_empty() && title != lobby_name {
                                            println!("lobby title: {title}");
                                        }
                                        if !welcome.is_empty() {
                                            println!("{welcome}");
                                        }
                                        println!(
                                            "received posts land in {}/lobbies/{}.log — 'lobby log' to read",
                                            root.display(),
                                            neonet::lobby::slug(&lobby_name)
                                        );
                                    }
                                    neonet::app::AppFrame::Lobby(
                                        neonet::app::lobby::LobbyFrame::Refuse { message },
                                    ) => println!(
                                        "{}{}{}",
                                        neonet::shell::RED,
                                        format_args!("{host_device_id} refused the lobby key: {message}"),
                                        neonet::shell::RESET
                                    ),
                                    other => println!(
                                        "{}{:?}{}",
                                        neonet::shell::RED,
                                        other,
                                        neonet::shell::RESET
                                    ),
                                }
                            }
                            "say" | "post" => {
                                let explicit = command == "post"
                                    && args.len() >= 2
                                    && neonet::lobby::find_roster(&root, &args[0]).is_some();
                                let (lobby_name, text) = if explicit {
                                    (args[0].clone(), args[1..].join(" "))
                                } else {
                                    let text = args.join(" ");
                                    if text.is_empty() {
                                        println!("usage: say TEXT  (active lobby)  |  post LOBBY TEXT");
                                        continue;
                                    }
                                    match neonet::lobby::last_roster(&root) {
                                        Some(active) => (active.name.clone(), text),
                                        None => {
                                            println!(
                                                "{}not a member of any lobby — 'join LOBBY HOST_KEY_ALIAS LOBBY_KEY' first{}",
                                                neonet::shell::RED,
                                                neonet::shell::RESET
                                            );
                                            continue;
                                        }
                                    }
                                };
                                let roster = match neonet::lobby::find_roster(&root, &lobby_name) {
                                    Some(roster) => roster,
                                    None => {
                                        println!(
                                            "{}{}{}",
                                            neonet::shell::RED,
                                            format_args!("not a member of lobby '{lobby_name}' — 'join' it first"),
                                            neonet::shell::RESET
                                        );
                                        continue;
                                    }
                                };
                                let Some(key) = hex::decode(&roster.key_hex)
                                    .ok()
                                    .and_then(|bytes| bytes.try_into().ok())
                                else {
                                    println!("{}lobby roster holds a corrupt key{}", neonet::shell::RED, neonet::shell::RESET);
                                    continue;
                                };
                                let (nonce, ciphertext) = match neonet::lobby::encrypt(&key, text.as_bytes()) {
                                    Ok(pair) => pair,
                                    Err(err) => {
                                        println!("{}{}{}", neonet::shell::RED, err, neonet::shell::RESET);
                                        continue;
                                    }
                                };
                                let reply = session
                                    .call(
                                        &root,
                                        &roster.host_alias,
                                        neonet::app::AppFrame::Lobby(
                                            neonet::app::lobby::LobbyFrame::Post {
                                                lobby_name: lobby_name.clone(),
                                                key: roster.key_hex.clone(),
                                                nonce,
                                                ciphertext,
                                            },
                                        ),
                                    )
                                    .await;
                                match reply {
                                    Ok(reply) => match neonet::app::AppFrame::decode(&reply.payload) {
                                        neonet::app::AppFrame::Lobby(
                                            neonet::app::lobby::LobbyFrame::Posted { relayed, .. },
                                        ) => {
                                            println!(
                                                "posted to '{lobby_name}' (relayed to {relayed} member(s))."
                                            );
                                        }
                                        neonet::app::AppFrame::Lobby(
                                            neonet::app::lobby::LobbyFrame::Refuse { message },
                                        ) => println!(
                                            "{}{}{}",
                                            neonet::shell::RED,
                                            format_args!("the lobby refused the post: {message}"),
                                            neonet::shell::RESET
                                        ),
                                        other => println!(
                                            "{}{:?}{}",
                                            neonet::shell::RED,
                                            other,
                                            neonet::shell::RESET
                                        ),
                                    },
                                    Err(err) => println!("{}{}{}", neonet::shell::RED, err, neonet::shell::RESET),
                                }
                            }
                            "lobby" => {
                                let subcommand = args.first().map(String::as_str).unwrap_or("");
                                let name = args.get(1).cloned().or_else(|| {
                                    neonet::lobby::last_roster(&root).map(|lobby| lobby.name.clone())
                                });
                                let name = match name {
                                    Some(name) => name,
                                    None => {
                                        println!("not a member of any lobby yet — 'join' one first");
                                        continue;
                                    }
                                };
                                let Some(roster) = neonet::lobby::find_roster(&root, &name) else {
                                    println!(
                                        "{}{}{}",
                                        neonet::shell::RED,
                                        format_args!("not a member of lobby '{name}' — 'join' it first"),
                                        neonet::shell::RESET
                                    );
                                    continue;
                                };
                                match subcommand {
                                    "log" => {
                                        let lines = neonet::lobby::read_lobby(&root, &name);
                                        if lines.is_empty() {
                                            println!(
                                                "lobby '{name}' (host {}) has no received posts logged yet.",
                                                roster.host_fingerprint
                                            );
                                        } else {
                                            for line in lines {
                                                println!("{}\t{}\t{}", line.at, line.sender, line.text);
                                            }
                                        }
                                    }
                                    "members" => {
                                        let reply = session
                                            .call(
                                                &root,
                                                &roster.host_alias,
                                                neonet::app::AppFrame::Lobby(
                                                    neonet::app::lobby::LobbyFrame::Members {
                                                        lobby_name: name.clone(),
                                                    },
                                                ),
                                            )
                                            .await;
                                        match reply {
                                            Ok(reply) => match neonet::app::AppFrame::decode(&reply.payload) {
                                                neonet::app::AppFrame::Lobby(
                                                    neonet::app::lobby::LobbyFrame::MemberList {
                                                        fingerprints,
                                                    },
                                                ) => {
                                                    if fingerprints.is_empty() {
                                                        println!("<none>");
                                                    } else {
                                                        for fingerprint in fingerprints {
                                                            println!("{fingerprint}");
                                                        }
                                                    }
                                                }
                                                neonet::app::AppFrame::Lobby(
                                                    neonet::app::lobby::LobbyFrame::Refuse { message },
                                                ) => println!(
                                                    "{}{}{}",
                                                    neonet::shell::RED,
                                                    message,
                                                    neonet::shell::RESET
                                                ),
                                                other => println!(
                                                    "{}{:?}{}",
                                                    neonet::shell::RED,
                                                    other,
                                                    neonet::shell::RESET
                                                ),
                                            },
                                            Err(err) => println!("{}{}{}", neonet::shell::RED, err, neonet::shell::RESET),
                                        }
                                    }
                                    "leave" => {
                                        let reply = session
                                            .call(
                                                &root,
                                                &roster.host_alias,
                                                neonet::app::AppFrame::Lobby(
                                                    neonet::app::lobby::LobbyFrame::Leave {
                                                        lobby_name: name.clone(),
                                                    },
                                                ),
                                            )
                                            .await;
                                        match reply {
                                            Ok(reply) => match neonet::app::AppFrame::decode(&reply.payload) {
                                                neonet::app::AppFrame::Lobby(
                                                    neonet::app::lobby::LobbyFrame::Left { .. },
                                                ) => println!("left lobby '{name}'."),
                                                neonet::app::AppFrame::Lobby(
                                                    neonet::app::lobby::LobbyFrame::Refuse { message },
                                                ) => println!(
                                                    "{}{}{}",
                                                    neonet::shell::RED,
                                                    message,
                                                    neonet::shell::RESET
                                                ),
                                                other => println!(
                                                    "{}{:?}{}",
                                                    neonet::shell::RED,
                                                    other,
                                                    neonet::shell::RESET
                                                ),
                                            },
                                            Err(err) => println!("{}{}{}", neonet::shell::RED, err, neonet::shell::RESET),
                                        }
                                    }
                                    _ => println!(
                                        "usage: lobby log [NAME] | lobby members [NAME] | lobby leave [NAME]"
                                    ),
                                }
                            }

                            // ---- infrastructure daemons & self-update ----
                            "core" | "serve" | "edge" => {
                                let daemon = command.as_str();
                                if args.is_empty() {
                                    let usage = if daemon == "edge" {
                                        "usage: edge --bootstrap FILE"
                                    } else {
                                        "usage: core --listen ADDR [--allow-file FILE]  (serve is an alias)"
                                    };
                                    println!("{usage}");
                                    continue;
                                }
                                let argv = args.to_vec();
                                match spawn_daemon(&root, daemon, &argv) {
                                    Ok((pid, log_path)) => println!(
                                        "{}neonet {daemon} launched in background (pid {pid}) — log: {}{}",
                                        neonet::shell::GREEN,
                                        log_path.display(),
                                        neonet::shell::RESET
                                    ),
                                    Err(err) => println!("{}{}{}", neonet::shell::RED, err, neonet::shell::RESET),
                                }
                            }
                            "daemons" => {
                                let daemons = list_daemons(&root);
                                if daemons.is_empty() {
                                    println!("no daemons launched from this shell yet — 'core', 'serve', 'edge'.");
                                } else {
                                    for (name, pid, log) in daemons {
                                        println!("{pid}\t{name}\t{log}");
                                    }
                                    println!("stop one with 'stop PID'.");
                                }
                            }
                            "stop" => {
                                let pid_text = args.first().map(String::as_str).unwrap_or("");
                                let pid = match pid_text.parse::<u32>() {
                                    Ok(pid) => pid,
                                    Err(_) => {
                                        println!("usage: stop PID  (see 'daemons')");
                                        continue;
                                    }
                                };
                                match std::process::Command::new("kill")
                                    .arg(pid_text)
                                    .status()
                                {
                                    Ok(status) if status.success() => {
                                        let remaining = list_daemons(&root)
                                            .into_iter()
                                            .filter(|(_, known, _)| *known != pid)
                                            .collect::<Vec<_>>();
                                        if let Err(err) = save_daemons(&root, &remaining) {
                                            println!("{}{}{}", neonet::shell::RED, err, neonet::shell::RESET);
                                        }
                                        println!("stopped pid {pid}.");
                                    }
                                    Ok(_) => println!(
                                        "{}{}{}",
                                        neonet::shell::RED,
                                        format_args!("kill did not stop pid {pid}"),
                                        neonet::shell::RESET
                                    ),
                                    Err(err) => println!("{}{}{}", neonet::shell::RED, err, neonet::shell::RESET),
                                }
                            }
                            "update" => {
                                let repo = flag_value(args, "--repo");
                                let branch = flag_value(args, "--branch");
                                let release = args.iter().any(|arg| arg == "--release");
                                match neonet::update::run(repo.as_deref(), branch.as_deref(), release) {
                                    Ok(()) => {}
                                    Err(err) => println!(
                                        "{}{:#}{}",
                                        neonet::shell::RED,
                                        err,
                                        neonet::shell::RESET
                                    ),
                                }
                            }
                            other => {
                                println!(
                                    "{}'{}' is not recognized as a command{}",
                                    neonet::shell::RED,
                                    other,
                                    neonet::shell::RESET,
                                );
                                println!("Type 'help' for the command list.");
                            }
                        }

                        if quit {
                            break;
                        }
                        continue;
                    }
                }
            }

            let _ = stdin_reader.join();
            println!();
            if let Err(err) = history.save(&root) {
                println!("{}{}{}", neonet::shell::RED, err, neonet::shell::RESET);
            }
            println!("History saved. Shell closed.");
        }
        Some(Command::Update {
            repo,
            branch,
            release,
        }) => {
            neonet::update::run(repo.as_deref(), branch.as_deref(), release)?;
        }
    }
    Ok(())
}

#[tokio::main]
async fn main() {
    if let Err(err) = run().await {
        // {:#} prints anyhow's full context chain ("could not X: could not Y:
        // <original error>") instead of a bare Debug dump of the innermost
        // std error, which is what `fn main() -> Result<_, _>` gives you by
        // default and is why raw errors like `Os { code: 2, ... }` used to
        // reach the terminal with no explanation of what NeoNet was doing
        // when they happened.
        eprintln!("Error: {err:#}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn remote_paths_join_and_normalize_without_absolutes() {
        // Root is the empty string and lists as ".".
        assert_eq!(join_remote_path("", "."), "");
        assert_eq!(join_remote_path("", ""), "");
        assert_eq!(join_remote_path("", "share"), "share");
        // Nested from a cwd.
        assert_eq!(join_remote_path("share", "sub"), "share/sub");
        // .. pops back toward the root without ever going negative.
        assert_eq!(join_remote_path("share/sub", ".."), "share");
        assert_eq!(join_remote_path("share", "../.."), "");
        assert_eq!(join_remote_path("", ".."), "");
        assert_eq!(join_remote_path("share", "/deep/../../x"), "x");
        // Repeat slashes and dots collapse.
        assert_eq!(join_remote_path("", "./a//b/./c"), "a/b/c");
    }

    #[test]
    fn remote_cwd_displays_slash_for_root() {
        assert_eq!(remote_cwd_display(""), "/");
        assert_eq!(remote_cwd_display("share"), "/share");
        assert_eq!(remote_cwd_display("share/sub"), "/share/sub");
    }
}
