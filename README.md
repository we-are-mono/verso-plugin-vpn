# verso-plugin-vpn

VPN for [Verso](https://github.com/we-are-mono/verso), the web interface for
OpenWrt: one VPN page listing every tunnel on the router, whatever runs it,
with each OpenVPN profile read out and its sign-in edited in place.

It is a non-core Verso plugin: a package of its own, installed only where you
want it. Once installed its page joins Verso's sidebar under VPN; removed, it
leaves it. Like every Verso plugin it runs as its own process, describes its
pages with Verso's widgets, and reads and writes the router only through rpcd
and the access list it ships.

A tunnel's state is what OpenVPN itself reports: this package installs the
OpenVPN hotplug hook that records it, and its root half reads it. The root half
is this plugin's own binary run as root by Verso's helper, for the commands the
package registers in `/usr/share/verso/plugins/vpn/commands.json` (Verso
ADR-027):

- `state`, a read: each OpenVPN instance's profile read out with its key blocks
  folded, whether it runs and on which device, what OpenVPN last reported, and
  every tunnel device as the kernel holds it;
- `files`, the `openvpn` file family's transform: the profiles in
  `/etc/openvpn` listed folded, a file no instance reads as its profile listed
  by its name alone, and a saved profile given its folded blocks back.

Nothing secret leaves the root half.

### `vpn.state`, version 1

`{"instances": {"proton": {"config": "/etc/openvpn/proton.ovpn", "running": true, "state": "connected", "since": 1791295321, "server": "185.107.56.234:1194", "address": "10.96.0.14/16", "device": "tun0", "profile": {...}}}, "tunnels": [{"device": "tun0", "kind": "openvpn", "instance": "proton", "up": true, "rx": 1331000000, "tx": 190800000, "addresses": ["10.96.0.14/16"]}]}`

- **Instances and tunnels.** Each `openvpn` section that names a profile file,
  and every tunnel device someone brought up (the kernel's own `sit0` and kin
  left out).
- **`state`** is what OpenVPN itself last reported through the hooks OpenWrt's
  init wires to every instance (`/etc/hotplug.d/openvpn/50-verso`, recording
  into `/var/run/verso-openvpn`):
  - `connected` at `route-up`;
  - `connecting` from `up` or `route-pre-down` (a reconnect under `persist-tun`);
  - `stopped` without a process.

  Where OpenVPN has reported nothing this run (the hook arrived after the tunnel
  came up, or the profile sets `script-security` below 2), it is what the kernel
  proves over rtnetlink: `up` when the tun device carries an IPv4 address,
  otherwise `connecting`.
- **Which record counts.** A record counts only when it carries the running
  process's PID and was written by one of two writers:
  - root, which runs OpenVPN's first hooks and records under the instance's name;
  - the user a profile drops to, which runs the hooks after, records under the
    name and its uid (`proton.65534`), and carries root's record of the run over.

  The user's record is read first.
- **The other fields.** `since` (an epoch second, connected only) and `server`
  come from the hook and are absent without it. `address` is the device's while
  it has one. `device` is the tun device the process holds. No state is read from
  the log.
- **`profile`** reads the file out: `client`, `dev`, `proto`, `remotes` (`host`,
  `port`, `proto`), `random`, `cipher`, `verify`, `asks_sign_in`, `redirect`,
  `nopull`, `blocks` (the inline block names) and `text`, the file folded as the
  listing folds it. The facts come from the lines outside the blocks; `remotes`
  and `proto` also come from each `<connection>` block's own options (a block
  inline in one left out), the block itself still folded.
- **Secrets.** Profiles are read only under `/etc/openvpn`. Key blocks and
  sign-in files never leave the root half.
- **`kind`.** A tunnel's `kind` is `openvpn`, `wireguard`, `tailscale` or
  `tunnel`.

### The `openvpn` family's files

OpenVPN's profiles are `.ovpn` and `.conf` files directly in `/etc/openvpn`,
listed through Verso's `configFiles` read as they will read once staged changes
are applied.

- **Which files are opened.** A file there is read as a profile only when an
  `openvpn` section names that exact path as its `config`, or it is staged. Any
  other file (a sign-in file saved as `.conf`, say, which holds no block to fold)
  is listed by its `path` alone and never opened, so its name stays taken and
  nothing in it leaves root.
- **Folding.** `content` has every inline block folded to one line
  (`<tls-crypt> … 18 lines … </tls-crypt>`): every block OpenVPN would read
  inline, whatever its name (a `<connection>` block folds whole). A block is
  found as OpenVPN finds it:
  - it opens on a line whose only token is `<name>`, after OpenVPN's quoting,
    comments and leading `--`, read in OpenVPN's own line-buffer pieces;
  - it closes at the first line that starts with `</name>` past C whitespace.
- **Saving.** A save puts each placeholder left as it was back to its original
  block, so an editor that never saw a key keeps it. A save is refused when it
  would:
  - put a block back where OpenVPN no longer reads it inline (a BOM-led opener
    moved off the first line, or with a line added above it);
  - have a line of a block open a block it did not open before (a block opened
    above the placeholder and closed by a hidden `</name>`), whose `<name>` the
    next listing would show as the placeholder.

  A new profile is written readable by root only.

## Install

On a router running Verso, from the Verso package feed:

```sh
apk update
apk add verso-plugin-vpn
```

The package depends on `verso` and `openvpn`, which every OpenVPN build
provides, so a router keeps the one it has.

## Build

The plugin is a static Rust binary built on Verso's plugin SDK, which Cargo
reads from the Verso checkout beside it (`../verso-plugin-sdk`).
`rust-toolchain.toml` provisions the compiler and both musl targets; nothing
else is needed but `rustup` and `make`.

```sh
make test     # unit and page tests
make lint     # clippy, warnings as errors
make build    # build/verso-plugin-vpn-{amd64,arm64}
make apk      # a signed package for the router (needs an OpenWrt buildroot)
```

`make apk` takes the apk tool and the signing key from an OpenWrt buildroot:
pass `OPENWRT_DIR=/path/to/openwrt/source`, or set it in a gitignored
`local.mk`. The version is the latest `vX.Y.Z` tag and the commits on it
(`make version`).

## Layout

- `src/` — the plugin: its page, the router reads behind it, and tests
- `manifest.json` — what the shell discovers: the page and its socket
- `i18n/` — its translations, one catalog per language
- `rootfs/` — what the package installs as it stands: the init script and the
  rpcd access list
- `packaging/post-install.sh` — enables and starts the plugin's service

## License

GPL-2.0-only. See `LICENSE`.
