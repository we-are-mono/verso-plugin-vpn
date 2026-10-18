// SPDX-License-Identifier: GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Mono Technologies Inc.

//! The plugin's root half (ADR-027): `verso-plugin-vpn root`, run by the
//! privileged helper as root for the commands rootfs's `commands.json`
//! registers.
//!
//! - `state` (a read): what the tunnels are doing, with each profile read out
//!   and folded.
//! - `files` (the `openvpn` family's transform): a listing folds each profile
//!   and withholds any file no instance reads as its profile; a save puts the
//!   folded blocks back, or is refused where OpenVPN would read them otherwise.

use crate::openvpn;
use serde_json::{json, Map, Value};
use std::collections::BTreeSet;
use verso_plugin::root::{RootError, RootRequest};

/// The version of the `state` read: raised only when its result changes
/// incompatibly (ADR-027 §4).
pub const STATE_VERSION: u32 = 1;

/// The refusal of a save whose folded blocks cannot go back where OpenVPN
/// reads them as blocks.
pub const MOVED: &str = "A folded block was moved, or a line added before it, where OpenVPN would not read it as a block. Move it back, or paste the block in whole.";

/// The reason a file no instance reads as its profile is listed by its path
/// alone.
pub const NOT_A_PROFILE: &str = "No OpenVPN instance reads this file as its profile.";

pub fn run() -> ! {
    verso_plugin::root::run(&[("state", &state), ("files", &files)])
}

fn state(_: &RootRequest) -> Result<Map<String, Value>, RootError> {
    match openvpn::state() {
        Value::Object(map) => Ok(map),
        _ => Err(RootError::failure("the tunnels' state is not an object")),
    }
}

fn files(request: &RootRequest) -> Result<Map<String, Value>, RootError> {
    match request.input["op"].as_str() {
        Some("list") => Ok(list(&request.input, openvpn::profiles)),
        Some("stage") => stage(&request.input),
        _ => Err(RootError::failure("the files transform takes op list or stage")),
    }
}

/// list folds each listed profile, and withholds a file no instance reads as
/// its profile unless it is staged — a sign-in file above all, whatever it is
/// named, which fold would not hide. profiles is asked for once, and only when
/// a file is listed that is not staged.
fn list(input: &Value, profiles: impl FnOnce() -> BTreeSet<String>) -> Map<String, Value> {
    let empty = vec![];
    let listed = input["files"].as_array().unwrap_or(&empty);
    let mut named: Option<BTreeSet<String>> = None;
    let mut profiles = Some(profiles);
    let mut out = vec![];
    for file in listed {
        let path = file["path"].as_str().unwrap_or_default();
        let pending = file["pending"].as_bool().unwrap_or(false);
        if !pending {
            let named = named.get_or_insert_with(|| profiles.take().map(|p| p()).unwrap_or_default());
            if !named.contains(path) {
                out.push(json!({"path": path, "withheld": NOT_A_PROFILE}));
                continue;
            }
        }
        let content = openvpn::fold(file["content"].as_str().unwrap_or_default());
        out.push(json!({"path": path, "content": content}));
    }
    let mut map = Map::new();
    map.insert("files".into(), Value::Array(out));
    map
}

/// stage puts a saved profile's folded blocks back from what the file held.
fn stage(input: &Value) -> Result<Map<String, Value>, RootError> {
    let edited = input["edited"].as_str().unwrap_or_default();
    let previous = input["previous"].as_str().unwrap_or_default();
    let content = openvpn::unfold(edited, previous).ok_or_else(|| RootError::refusal(MOVED))?;
    let mut map = Map::new();
    map.insert("content".into(), json!(content));
    Ok(map)
}

#[cfg(test)]
mod tests {
    use super::*;
    use verso_plugin::Registry;

    const PROFILE: &str = "client\nremote a 1194\n<tls-crypt>\nKEY\n</tls-crypt>\n";

    #[test]
    fn a_listing_folds_profiles_and_withholds_the_rest() {
        let input = json!({"op": "list", "files": [
            {"path": "/etc/openvpn/proton.ovpn", "content": PROFILE, "pending": false},
            {"path": "/etc/openvpn/proton.conf", "content": "user\npass\n", "pending": false},
            {"path": "/etc/openvpn/new.ovpn", "content": PROFILE, "pending": true}
        ]});
        let out = list(&input, || ["/etc/openvpn/proton.ovpn".to_string()].into());
        let files = out["files"].as_array().unwrap();
        assert_eq!(files[0]["path"], "/etc/openvpn/proton.ovpn");
        assert!(!files[0]["content"].as_str().unwrap().contains("KEY"));
        assert_eq!(files[1], json!({"path": "/etc/openvpn/proton.conf", "withheld": NOT_A_PROFILE}));
        assert!(!files[2]["content"].as_str().unwrap().contains("KEY"), "a staged file is the page's own, folded");
    }

    #[test]
    fn a_listing_of_staged_files_alone_asks_uci_nothing() {
        let input = json!({"files": [{"path": "/etc/openvpn/new.ovpn", "content": PROFILE, "pending": true}]});
        let out = list(&input, || panic!("uci read for staged files"));
        assert_eq!(out["files"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn a_save_puts_the_blocks_back_or_is_refused() {
        let folded = openvpn::fold(PROFILE);
        let edited = folded.replace("remote a 1194", "remote b 443");
        let out = stage(&json!({"op": "stage", "edited": edited, "previous": PROFILE})).unwrap();
        assert_eq!(out["content"], PROFILE.replace("remote a 1194", "remote b 443"));
        // A block that opened only by its byte-order mark, moved off the first
        // line, would no longer be read as a block.
        let marked = "\u{feff}<key>\nSECRET\n</key>\nclient\n";
        let moved = "client\n<key> … 1 line … </key>\n";
        let refused = stage(&json!({"edited": moved, "previous": marked}));
        assert_eq!(refused.unwrap_err(), RootError::Refusal(MOVED.into()));
    }

    /// The registry the package installs registers what this half answers.
    #[test]
    fn the_registry_names_what_the_root_half_answers() {
        let text = std::fs::read_to_string("rootfs/usr/share/verso/plugins/vpn/commands.json").unwrap();
        let registry: Registry = serde_json::from_str(&text).unwrap();
        registry.check().unwrap();
        let names: Vec<&str> = registry.commands.iter().map(|c| c.name.as_str()).collect();
        assert_eq!(names, ["state", "files"]);
        assert_eq!(registry.commands[0].version, Some(STATE_VERSION));
        assert!(registry.commands.iter().all(|c| c.exec == "/usr/bin/verso-plugin-vpn" && c.argv == ["root"]));
        assert_eq!(registry.families[0].transform.as_deref(), Some("files"));
    }
}
