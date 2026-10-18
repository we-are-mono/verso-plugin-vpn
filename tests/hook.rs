// SPDX-License-Identifier: GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Mono Technologies Inc.

//! The OpenVPN hotplug hook this package ships, run as OpenWrt's hotplug-call
//! runs it — sourced in a subshell of busybox sh — against a record directory
//! as the hook makes it (1733), with whatever another account can stand there
//! first.

use std::collections::BTreeMap;
use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// The hook the package ships for hotplug-call to run on each OpenVPN
/// instance's transitions.
const HOOK: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/rootfs/etc/hotplug.d/openvpn/50-verso");

/// RUN runs the hook as hotplug-call does, sourced in a subshell, once $PLANT
/// ("fifo" or "file") has stood at .vpn1.<the shell's PID> in the record
/// directory, the name a hook taking its PID for a temporary name would write.
/// The name planted and its inode go to $PLANTED.
const RUN: &str = r#"D=$1 HOOK=$2
case $PLANT in
	fifo) mkfifo "$D/.vpn1.$$" ;;
	file) : >"$D/.vpn1.$$" ;;
esac
[ -n "$PLANT" ] && echo ".vpn1.$$ $(stat -c %i "$D/.vpn1.$$")" >"$PLANTED"
( . "$HOOK" )
"#;

/// AFTER_RECORD stands a record at vpn1, carrying the PID of the OpenVPN
/// about to run the hook and a since, server and address of the writer's
/// choosing, then runs the hook as hotplug-call does. It runs as root of a user
/// namespace that maps uid $PLANTER too: given one, the writer drops to it from
/// inside the record directory. Given $TARGET, the record is written there and
/// vpn1 is a link to it.
const AFTER_RECORD: &str = r#"D=$1 HOOK=$2
PATH=$HOOKPATH
cd "$D" || exit 1
plant='printf "pid=%s\nstate=connected\nsince=1\naddress=6.6.6.6\nserver=evil.example:443\ndevice=evil0\n" "$1" >"${TARGET:-vpn1}" &&
	{ [ -z "$TARGET" ] || "$BUSYBOX" ln -s "$TARGET" vpn1; }'
if [ -n "$PLANTER" ]; then
	"$SETPRIV" --reuid "$PLANTER" --regid "$PLANTER" --clear-groups "$BUSYBOX" sh -c "$plant" sh "$PPID"
else
	"$BUSYBOX" sh -c "$plant" sh "$PPID"
fi || exit 1
( . "$HOOK" )
"#;

/// DROPPED runs the hook as an OpenVPN that drops to uid 1001 runs it, every
/// run a child of this shell so each carries its PID: as root for route-up, as
/// 1001 for route-pre-down and an ipchange after. Given $PLANTER, root's
/// route-up does not run and that account stands a record at the instance's
/// name first, carrying the PID and a server of its choosing.
const DROPPED: &str = r#"D=$1 HOOK=$2
PATH=$HOOKPATH
cd "$D" || exit 1
hook='. "$1"'
if [ -n "$PLANTER" ]; then
	"$SETPRIV" --reuid "$PLANTER" --regid "$PLANTER" --clear-groups "$BUSYBOX" sh -c \
		'printf "pid=%s\nstate=connected\nsince=1\naddress=6.6.6.6\nserver=evil.example:443\n" "$1" >vpn1' sh "$$" || exit 1
else
	ACTION=route-up dev=tun0 ifconfig_local=10.8.0.2 trusted_ip=192.0.2.1 trusted_port=1194 \
		"$BUSYBOX" sh -c "$hook" sh "$HOOK" || exit 1
fi
as1001() { "$SETPRIV" --reuid 1001 --regid 1001 --clear-groups "$BUSYBOX" env "$@" "$BUSYBOX" sh -c "$hook" sh "$HOOK"; }
as1001 ACTION=route-pre-down || exit 1
cp vpn1.1001 "$OUT/pre-down" || exit 1
as1001 ACTION=ipchange trusted_ip=192.0.2.9 trusted_port=1194 || exit 1
"#;

/// A run of the hook still going after this is one a planted FIFO blocked.
const TIMEOUT: Duration = Duration::from_secs(5);

/// Scratch is a directory of this test's own, one level inside another of its
/// own, so every directory a test opens to a dropped user is this test's; both
/// are removed when dropped.
struct Scratch {
    outer: PathBuf,
    inner: PathBuf,
}

impl Scratch {
    fn new(name: &str) -> Scratch {
        let outer = std::env::temp_dir().join(format!("vpn-hook-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&outer);
        fs::create_dir_all(outer.join("s")).unwrap();
        let outer = fs::canonicalize(outer).unwrap();
        Scratch { inner: outer.join("s"), outer }
    }
    fn path(&self) -> &Path {
        &self.inner
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        // A dropped user's record directory may hold files this account cannot
        // remove; the next run's new() clears what it can.
        let _ = fs::remove_dir_all(&self.outer);
    }
}

fn which(program: &str) -> Option<PathBuf> {
    std::env::var_os("PATH")?
        .to_str()?
        .split(':')
        .map(|dir| Path::new(dir).join(program))
        .find(|p| p.is_file())
}

/// records is a record directory as the hook makes it, 1733, and a copy of
/// the hook pointed at it.
fn records(scratch: &Scratch) -> (PathBuf, PathBuf) {
    let dir = scratch.path().join("records");
    fs::create_dir(&dir).unwrap();
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o1733)).unwrap();
    let script = fs::read_to_string(HOOK).unwrap();
    let named = "dir=/var/run/verso-openvpn\n";
    assert!(script.contains(named), "{HOOK} names no record directory");
    let hook = scratch.path().join("50-verso");
    fs::write(&hook, script.replacen(named, &format!("dir={}\n", dir.display()), 1)).unwrap();
    (dir, hook)
}

/// busybox_path is a directory of the commands the hook and its harness call,
/// each busybox, as on the router.
fn busybox_path(scratch: &Scratch, busybox: &Path) -> PathBuf {
    let bin = scratch.path().join("bin");
    fs::create_dir_all(&bin).unwrap();
    for applet in ["chmod", "cp", "date", "id", "ls", "mkdir", "mkfifo", "mktemp", "mv", "rm", "stat"] {
        let _ = std::os::unix::fs::symlink(busybox, bin.join(applet));
    }
    bin
}

fn my_uid() -> u32 {
    let status = fs::read_to_string("/proc/self/status").unwrap();
    let line = status.lines().find(|l| l.starts_with("Uid:")).unwrap();
    line.split_whitespace().nth(1).unwrap().parse().unwrap()
}

/// record_of is the name the hook writes instance's record under when it runs
/// as uid: the instance's name for root, the name and the uid otherwise.
fn record_of(instance: &str, uid: u32) -> String {
    if uid == 0 {
        instance.into()
    } else {
        format!("{instance}.{uid}")
    }
}

/// run runs a command to its end within TIMEOUT, killing it past that, and
/// answers whether it succeeded and what it said.
fn run(mut command: Command) -> (bool, String) {
    command.stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped());
    let mut child = command.spawn().unwrap();
    let started = Instant::now();
    loop {
        if let Some(_status) = child.try_wait().unwrap() {
            let out = child.wait_with_output().unwrap();
            let said = String::from_utf8_lossy(&[out.stdout, out.stderr].concat()).into_owned();
            return (out.status.success(), said);
        }
        if started.elapsed() > TIMEOUT {
            let _ = child.kill();
            let _ = child.wait();
            panic!("the hook still ran after {TIMEOUT:?}: something planted blocked it");
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// What the harness stood in the record directory: its name and inode.
#[derive(Default)]
struct Planted {
    name: String,
    inode: u64,
}

/// run_hook runs the hook for instance vpn1's up under busybox sh, plant
/// ("", "fifo" or "file") standing first at the name a PID-named temporary
/// would take, and answers what was planted.
fn run_hook(scratch: &Scratch, busybox: &Path, dir: &Path, hook: &Path, plant: &str) -> Planted {
    let planted = scratch.path().join("planted");
    let mut command = Command::new(busybox);
    command
        .args(["sh", "-c", RUN, "sh"])
        .arg(dir)
        .arg(hook)
        .env_clear()
        .env("PATH", busybox_path(scratch, busybox))
        .env("PLANT", plant)
        .env("PLANTED", &planted)
        .env("INSTANCE", "vpn1")
        .env("ACTION", "up")
        .env("dev", "tun0")
        .env("ifconfig_local", "10.8.0.2")
        .env("trusted_ip", "192.0.2.1");
    let (ok, said) = run(command);
    assert!(ok, "hook: {said}");
    if plant.is_empty() {
        return Planted::default();
    }
    let line = fs::read_to_string(&planted).unwrap();
    let (name, inode) = line.trim().split_once(' ').unwrap();
    Planted { name: name.into(), inode: inode.parse().unwrap() }
}

/// The record directory takes anyone's file, so whatever another account
/// stands at a name the hook could guess neither holds the hook up (a FIFO
/// would block its write forever, and OpenVPN with it) nor becomes the record
/// (a file of theirs the hook wrote into and renamed in place). The record is
/// a file the hook made, carrying the PID of the OpenVPN that ran it, and the
/// hook leaves no temporary of its own behind.
#[test]
fn the_hook_writes_its_record_past_what_others_plant() {
    let Some(busybox) = which("busybox") else {
        eprintln!("skipped: the hook runs under busybox sh, which is not installed");
        return;
    };
    for plant in ["", "fifo", "file"] {
        let scratch = Scratch::new(&format!("plant-{plant}"));
        let (dir, hook) = records(&scratch);
        let stood = run_hook(&scratch, &busybox, &dir, &hook, plant);

        let name = record_of("vpn1", my_uid());
        let record = dir.join(&name);
        let meta = fs::symlink_metadata(&record).expect("a record");
        assert!(meta.file_type().is_file(), "{plant}: the record is not a regular file");
        assert!(stood.name.is_empty() || meta.ino() != stood.inode, "{plant}: the record is the planted {}", stood.name);
        let text = fs::read_to_string(&record).unwrap();
        let pid = format!("pid={}", std::process::id());
        for line in [pid.as_str(), "state=connecting", "address=10.8.0.2", "server=192.0.2.1:1194", "device=tun0"] {
            assert!(text.contains(&format!("{line}\n")), "{plant}: record {text:?} holds no {line:?}");
        }
        for entry in fs::read_dir(&dir).unwrap() {
            let entry = entry.unwrap().file_name().into_string().unwrap();
            assert!(entry == name || entry == stood.name, "{plant}: the hook left {entry} behind");
        }
    }
}

/// A directory standing at the record's name, even one open to the hook, is
/// not a place to rename the record into; the hook leaves both directories as
/// it found them.
#[test]
fn the_hook_removes_its_temporary_when_the_record_cannot_be_replaced() {
    let Some(busybox) = which("busybox") else {
        eprintln!("skipped: the hook runs under busybox sh, which is not installed");
        return;
    };
    let scratch = Scratch::new("replace");
    let (dir, hook) = records(&scratch);
    let name = record_of("vpn1", my_uid());
    let stood = dir.join(&name);
    fs::create_dir(&stood).unwrap();
    fs::set_permissions(&stood, fs::Permissions::from_mode(0o777)).unwrap();
    run_hook(&scratch, &busybox, &dir, &hook, "");
    let entries: Vec<String> = fs::read_dir(&dir).unwrap().map(|e| e.unwrap().file_name().into_string().unwrap()).collect();
    assert_eq!(entries, [name], "the record directory holds more than the directory at the record's name");
    assert_eq!(fs::read_dir(&stood).unwrap().count(), 0, "the directory at the record's name took a file");
}

/// The unshare and setpriv a test runs the hook with as root of a user
/// namespace that maps uids 1001 and 1002 too, or None where there is none.
fn user_namespace() -> Option<(PathBuf, PathBuf)> {
    let unshare = which("unshare")?;
    let setpriv = which("setpriv")?;
    for uid in ["1001", "1002"] {
        let probe = Command::new(&unshare)
            .args(["--map-root-user", "--map-auto"])
            .arg(&setpriv)
            .args(["--reuid", uid, "--regid", uid, "--clear-groups", "true"])
            .output()
            .ok()?;
        if !probe.status.success() {
            return None;
        }
    }
    Some((unshare, setpriv))
}

/// What an instance carries from one hook to the next (since, address,
/// server) comes only from a record the hook's own user wrote. A record
/// another account stood at the instance's name before the first hook ran,
/// with the right PID, would otherwise pass its server and address into the
/// record the hook writes, which the reader trusts as the instance's own.
#[test]
fn the_hook_carries_over_only_its_own_record() {
    let (Some(busybox), Some((unshare, setpriv))) = (which("busybox"), user_namespace()) else {
        eprintln!("skipped: another account's record needs busybox, unshare, setpriv and a user namespace");
        return;
    };
    for (name, planter, target, carried) in [
        ("own", "", "", ["since=1", "address=6.6.6.6", "server=evil.example:443"]),
        ("another", "1001", "", ["since=", "address=", "server="]),
        ("link", "", "vpn1.real", ["since=", "address=", "server="]),
    ] {
        let scratch = Scratch::new(&format!("carry-{name}"));
        let (dir, hook) = records(&scratch);
        let mut command = Command::new(&unshare);
        command
            .args(["--map-root-user", "--map-auto"])
            .arg(&busybox)
            .args(["sh", "-c", AFTER_RECORD, "sh"])
            .arg(&dir)
            .arg(&hook)
            .env_clear()
            .env("PATH", std::env::var_os("PATH").unwrap())
            .env("HOOKPATH", busybox_path(&scratch, &busybox))
            .env("BUSYBOX", &busybox)
            .env("SETPRIV", &setpriv)
            .env("PLANTER", planter)
            .env("TARGET", target)
            .env("INSTANCE", "vpn1")
            .env("ACTION", "up")
            .env("dev", "tun0")
            .env("trusted_ip6", "2001:db8::1");
        let (ok, said) = run(command);
        assert!(ok, "{name}: hook: {said}");

        let record = dir.join("vpn1");
        let meta = fs::symlink_metadata(&record).unwrap();
        assert!(meta.file_type().is_file(), "{name}: the record is not a regular file");
        assert_eq!(meta.uid(), my_uid(), "{name}: the record is not the hook's own");
        let text = fs::read_to_string(&record).unwrap();
        for line in ["state=connecting"].iter().chain(carried.iter()).chain(["device=tun0"].iter()) {
            assert!(text.contains(&format!("\n{line}\n")), "{name}: record {text:?} holds no {line:?}");
        }
    }
}

/// An OpenVPN with a profile's user runs route-up as root and the hooks after
/// as that user, which cannot replace root's record in the 1733 directory. The
/// user's hooks write the instance's record under its name and their uid,
/// carrying over since, address and server from root's record of the same run,
/// so a reconnect and a server change still reach the reader. A record at
/// root's name that another account wrote is carried over by no one.
#[test]
fn the_hook_after_dropping_privileges_carries_roots_record() {
    let (Some(busybox), Some((unshare, setpriv))) = (which("busybox"), user_namespace()) else {
        eprintln!("skipped: a dropped user's record needs busybox, unshare, setpriv and a user namespace");
        return;
    };
    let cases: [(&str, &str, Vec<&str>, Vec<&str>); 2] = [
        (
            "root's",
            "",
            vec!["state=connecting", "address=10.8.0.2", "server=192.0.2.1:1194", "device=tun0"],
            vec!["state=connecting", "address=10.8.0.2", "server=192.0.2.9:1194", "device=tun0"],
        ),
        (
            "another account's",
            "1002",
            vec!["state=connecting", "since=", "address=", "server=", "device="],
            vec!["state=connecting", "since=", "address=", "server=192.0.2.9:1194", "device="],
        ),
    ];
    for (i, (name, planter, pre_down, ipchanged)) in cases.into_iter().enumerate() {
        let scratch = Scratch::new(&format!("dropped-{i}"));
        let (dir, hook) = records(&scratch);
        // The user OpenVPN drops to reaches the hook and the record directory
        // by their paths, as on the router.
        let mut at = dir.parent().unwrap().to_path_buf();
        for _ in 0..2 {
            fs::set_permissions(&at, fs::Permissions::from_mode(0o711)).unwrap();
            at = at.parent().unwrap().to_path_buf();
        }
        let out = scratch.path().join("out");
        fs::create_dir(&out).unwrap();
        fs::set_permissions(&out, fs::Permissions::from_mode(0o777)).unwrap();
        let mut command = Command::new(&unshare);
        command
            .args(["--map-root-user", "--map-auto"])
            .arg(&busybox)
            .args(["sh", "-c", DROPPED, "sh"])
            .arg(&dir)
            .arg(&hook)
            .env_clear()
            .env("PATH", std::env::var_os("PATH").unwrap())
            .env("HOOKPATH", busybox_path(&scratch, &busybox))
            .env("BUSYBOX", &busybox)
            .env("SETPRIV", &setpriv)
            .env("PLANTER", planter)
            .env("OUT", &out)
            .env("INSTANCE", "vpn1");
        let (ok, said) = run(command);
        // Put the walk back before anything can fail, so the scratch is removable.
        let mut at = dir.parent().unwrap().to_path_buf();
        for _ in 0..2 {
            let _ = fs::set_permissions(&at, fs::Permissions::from_mode(0o755));
            at = at.parent().unwrap().to_path_buf();
        }
        assert!(ok, "{name}: hook: {said}");

        let roots = fs::read_to_string(dir.join("vpn1")).unwrap();
        let since = roots.lines().find_map(|l| l.strip_prefix("since=")).unwrap_or_default().to_string();
        let (mut pre_down, mut ipchanged): (Vec<String>, Vec<String>) =
            (pre_down.iter().map(|s| s.to_string()).collect(), ipchanged.iter().map(|s| s.to_string()).collect());
        if planter.is_empty() {
            assert!(roots.contains("\nstate=connected\n") && !since.is_empty(), "{name}: root's route-up record {roots:?}");
            pre_down.push(format!("since={since}"));
            ipchanged.push(format!("since={since}"));
        }
        let users = dir.join("vpn1.1001");
        let meta = fs::symlink_metadata(&users).unwrap();
        assert!(meta.file_type().is_file(), "{name}: the user's record is not a regular file");
        assert_ne!(meta.uid(), my_uid(), "{name}: the user's record is owned by root of the namespace");
        let files: BTreeMap<PathBuf, Vec<String>> = [(out.join("pre-down"), pre_down), (users, ipchanged)].into();
        for (file, want) in files {
            let text = fs::read_to_string(&file).unwrap();
            for line in want {
                assert!(text.contains(&format!("\n{line}\n")), "{name}: {}: record {text:?} holds no {line:?}", file.display());
            }
            assert!(!text.contains("evil"), "{name}: {}: record {text:?} carried another account's", file.display());
        }
    }
}
