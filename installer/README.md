# NeoNet installers

These installers configure NeoNet as an OS service. The installer does not
copy a private identity key: the NeoNet process generates its identity on the
target machine on first run. A bootstrap file, when supplied, contains only the
out-of-band trust anchor (address + pinned public key).

## Linux

From the extracted project root, the easiest developer install is:

```bash
./installer/install-linux.sh
```

The script builds `target/release/neonet` as the normal user if it is missing,
then re-enters through `sudo` to install the binary and systemd service.

You can also supply a prebuilt binary, an optional bootstrap file, and an
optional allow-list file:

```bash
./installer/install-linux.sh /path/to/neonet /path/to/bootstrap.json /path/to/allow.json
```

If Rust/Cargo is not installed, build the binary on another machine and pass
that binary to the installer.

The optional allow-list file is a JSON array of full 64-hex public keys
listing which peers this core accepts inbound connections from (the
`--allow-file` argument, see `docs/CLI.md#access-control`). Installing
without it leaves the core open to any authenticated peer — fine for a
private network, wrong for the open internet.

After installation:

```bash
systemctl status neonet.service
journalctl -u neonet.service -f
```

## macOS / Windows

The macOS and Windows installers expect a built NeoNet executable. They install
service definitions and do not generate or copy a shared private identity.
