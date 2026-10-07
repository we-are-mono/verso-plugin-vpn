# verso-plugin-vpn

VPN for [Verso](https://github.com/we-are-mono/verso), the web interface for
OpenWrt: one VPN page listing every tunnel on the router, whatever runs it,
with each OpenVPN profile read out and its sign-in edited in place.

It is a non-core Verso plugin: a package of its own, installed only where you
want it. Once installed its page joins Verso's sidebar under VPN; removed, it
leaves it. Like every Verso plugin it runs as its own process, describes its
pages with Verso's widgets, and reads and writes the router only through rpcd
and the access list it ships.

A tunnel's state is what OpenVPN itself reports: the verso package installs
the OpenVPN hotplug hook that records it, and Verso's helper reads it.

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
fetches from the Verso repository at the release this plugin pins.
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
