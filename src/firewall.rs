//! Privileged, per-UID firewall rules. This module is only compiled into the helper.
use std::{
    fs,
    io::{self, Read, Write},
    os::{fd::AsRawFd, unix::fs::OpenOptionsExt},
    path::Path,
    process::{Command, Stdio},
};

use ipnet::IpNet;
use serde_json::{Value, json};

const STATE: &str = "/var/lib/dropshit";
const NFT: &str = "/usr/sbin/nft";
const MAX_REQUEST: u64 = 262_144;

fn command(binary: &str, args: &[&str], input: Option<&str>) -> Result<String, String> {
    let mut child = Command::new(binary)
        .args(args)
        .stdin(if input.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("{binary}: {e}"))?;
    if let Some(text) = input {
        child
            .stdin
            .take()
            .ok_or("stdin missing")?
            .write_all(text.as_bytes())
            .map_err(|e| format!("{binary}: {e}"))?;
    }
    let output = child.wait_with_output().map_err(|e| e.to_string())?;
    if output.status.success() {
        Ok(String::from_utf8_lossy(&output.stdout).into_owned())
    } else {
        Err(format!(
            "{binary}: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ))
    }
}

fn backend() -> Result<&'static str, String> {
    let config = Path::new("/etc/dropshit/firewall.json");
    if config.exists() {
        let value: Value =
            serde_json::from_str(&fs::read_to_string(config).map_err(|e| e.to_string())?)
                .map_err(|e| e.to_string())?;
        if value.as_object().is_none_or(|o| o.len() != 1) {
            return Err("invalid backend configuration".into());
        }
        match value["backend"].as_str() {
            Some("nftables") if Path::new(NFT).exists() => return Ok("nftables"),
            Some("iptables")
                if [
                    "iptables",
                    "ip6tables",
                    "iptables-restore",
                    "ip6tables-restore",
                ]
                .iter()
                .all(|tool| Path::new(&format!("/usr/sbin/{tool}")).exists()) =>
            {
                return Ok("iptables");
            }
            Some("auto") => (),
            Some("nftables" | "iptables") => {
                return Err("configured firewall tools are missing".into());
            }
            _ => return Err("backend must be auto, nftables or iptables".into()),
        }
    }
    if Path::new(NFT).exists() {
        Ok("nftables")
    } else if [
        "iptables",
        "ip6tables",
        "iptables-restore",
        "ip6tables-restore",
    ]
    .iter()
    .all(|tool| Path::new(&format!("/usr/sbin/{tool}")).exists())
    {
        Ok("iptables")
    } else {
        Err("Установите nftables или iptables/ip6tables".into())
    }
}

fn parse_networks(value: &Value) -> Result<Vec<IpNet>, String> {
    let items = value.as_array().ok_or("networks must be an array")?;
    if items.len() > 4096 {
        return Err("too many networks".into());
    }
    let mut networks = Vec::new();
    for item in items {
        let text = item.as_str().ok_or("network must be text")?;
        if text.len() > 80 {
            return Err("network too long".into());
        }
        let net: IpNet = text.parse().map_err(|e| format!("invalid network: {e}"))?;
        if net.prefix_len() == 0 {
            return Err("default-route blocks are forbidden".into());
        }
        networks.push(net.trunc());
    }
    networks.sort();
    networks.dedup();
    Ok(networks)
}

fn nft_script(uid: u32, networks: &[IpNet]) -> String {
    let table = format!("dropshit_{uid}");
    let mut text = format!("destroy table inet {table}\n");
    if networks.is_empty() {
        return text;
    }
    text += &format!("table inet {table} {{\n");
    for (v4, name, kind) in [
        (true, "blocked4", "ipv4_addr"),
        (false, "blocked6", "ipv6_addr"),
    ] {
        let family: Vec<_> = networks
            .iter()
            .filter(|n| n.addr().is_ipv4() == v4)
            .map(ToString::to_string)
            .collect();
        if !family.is_empty() {
            text += &format!(
                "set {name} {{ type {kind}; flags interval; auto-merge; elements = {{ {} }} }}\n",
                family.join(", ")
            );
        }
    }
    text += "chain output { type filter hook output priority -10; policy accept;\n";
    for (v4, name, family) in [(true, "blocked4", "ip"), (false, "blocked6", "ip6")] {
        if networks.iter().any(|n| n.addr().is_ipv4() == v4) {
            text +=
                &format!("meta skuid {uid} {family} daddr @{name} udp dport 12000-64000 reject\n");
        }
    }
    text + "}\n}\n"
}

fn nft_apply(uid: u32, networks: &[IpNet]) -> Result<(), String> {
    command(NFT, &["-f", "-"], Some(&nft_script(uid, networks))).map(|_| ())
}

fn tool(family: u8, restore: bool) -> &'static str {
    #[cfg(test)]
    if std::env::var_os("DROPSHIT_KERNEL_IPTABLES").is_some() {
        return match (family, restore) {
            (4, false) => "/tmp/opencode/dropshit-iptables/usr/sbin/iptables-nft",
            (6, false) => "/tmp/opencode/dropshit-iptables/usr/sbin/ip6tables-nft",
            (4, true) => "/tmp/opencode/dropshit-iptables/usr/sbin/iptables-nft-restore",
            (6, true) => "/tmp/opencode/dropshit-iptables/usr/sbin/ip6tables-nft-restore",
            _ => unreachable!(),
        };
    }
    match (family, restore) {
        (4, false) => "/usr/sbin/iptables",
        (6, false) => "/usr/sbin/ip6tables",
        (4, true) => "/usr/sbin/iptables-restore",
        (6, true) => "/usr/sbin/ip6tables-restore",
        _ => unreachable!(),
    }
}

fn iptables_snapshot(uid: u32, family: u8) -> Result<(bool, bool, Vec<IpNet>), String> {
    let chain = format!("DSHT_{uid}");
    let output = command(tool(family, false), &["-w", "-S"], None)?;
    let exists = output.lines().any(|line| line == format!("-N {chain}"));
    let hook = format!(
        "-A OUTPUT -p udp -m owner --uid-owner {uid} -m udp --dport 12000:64000 -j {chain}"
    );
    let attached = output.lines().any(|line| line == hook);
    if attached && !exists {
        return Err(format!("{chain}: jump exists without chain"));
    }
    let mut nets = Vec::new();
    for line in output
        .lines()
        .filter(|line| line.starts_with(&format!("-A {chain} ")))
    {
        let words: Vec<_> = line.split_whitespace().collect();
        if words.len() < 6
            || words[2] != "-d"
            || words[4..6] != ["-j", "REJECT"]
            || (words.len() > 6
                && words[6..]
                    != [
                        "--reject-with",
                        if family == 4 {
                            "icmp-port-unreachable"
                        } else {
                            "icmp6-port-unreachable"
                        },
                    ])
        {
            return Err(format!("unexpected rule in owned chain: {line}"));
        }
        let net: IpNet = words[3].parse().map_err(|e| format!("{line}: {e}"))?;
        nets.push(net);
    }
    // Don't silently treat a failed firewall query as a missing chain.
    Ok((exists, attached, nets))
}

fn iptables_write(
    uid: u32,
    family: u8,
    networks: &[IpNet],
    existed: bool,
    attached: bool,
) -> Result<(), String> {
    let chain = format!("DSHT_{uid}");
    let hook = format!("-p udp -m owner --uid-owner {uid} -m udp --dport 12000:64000 -j {chain}");
    let mut lines = vec!["*filter".to_owned()];
    if networks.is_empty() {
        if existed {
            if attached {
                lines.push(format!("-D OUTPUT {hook}"));
            }
            lines.push(format!("-F {chain}"));
            lines.push(format!("-X {chain}"));
        }
    } else {
        if !existed {
            lines.push(format!("-N {chain}"));
        } else {
            lines.push(format!("-F {chain}"));
        }
        for net in networks {
            lines.push(format!("-A {chain} -d {net} -j REJECT"));
        }
        if !attached {
            lines.push(format!("-I OUTPUT 1 {hook}"));
        }
    }
    lines.push("COMMIT".into());
    command(
        tool(family, true),
        &["--wait", "10", "--noflush"],
        Some(&(lines.join("\n") + "\n")),
    )
    .map(|_| ())
}

fn iptables_apply(uid: u32, nets: &[IpNet]) -> Result<(), String> {
    let old4 = iptables_snapshot(uid, 4)?;
    let old6 = iptables_snapshot(uid, 6)?;
    let new4: Vec<_> = nets
        .iter()
        .filter(|n| n.addr().is_ipv4())
        .copied()
        .collect();
    let new6: Vec<_> = nets
        .iter()
        .filter(|n| n.addr().is_ipv6())
        .copied()
        .collect();
    iptables_write(uid, 4, &new4, old4.0, old4.1)?;
    if let Err(error) = iptables_write(uid, 6, &new6, old6.0, old6.1) {
        let current4 = iptables_snapshot(uid, 4)?;
        iptables_write(uid, 4, &old4.2, current4.0, current4.1)
            .map_err(|rollback| format!("{error}; IPv4 rollback FAILED: {rollback}"))?;
        return Err(error);
    }
    Ok(())
}

fn apply(uid: u32, backend: &str, networks: &[IpNet]) -> Result<(), String> {
    match backend {
        "nftables" => nft_apply(uid, networks),
        "iptables" => iptables_apply(uid, networks),
        _ => Err("invalid backend".into()),
    }
}

fn state_path(uid: u32) -> String {
    format!("{STATE}/{uid}.json")
}

fn read_state(uid: u32) -> Result<Option<(String, Vec<IpNet>)>, String> {
    let text = match fs::read_to_string(state_path(uid)) {
        Ok(text) => text,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e.to_string()),
    };
    let value: Value = serde_json::from_str(&text).map_err(|e| e.to_string())?;
    let backend = value["backend"].as_str().ok_or("backend missing")?;
    if !["nftables", "iptables"].contains(&backend) {
        return Err("invalid saved backend".into());
    }
    Ok(Some((backend.into(), parse_networks(&value["networks"])?)))
}

fn save(uid: u32, backend: &str, nets: &[IpNet]) -> Result<(), String> {
    let path = state_path(uid);
    if nets.is_empty() {
        match fs::remove_file(path) {
            Ok(()) => (),
            Err(e) if e.kind() == io::ErrorKind::NotFound => (),
            Err(e) => return Err(e.to_string()),
        }
    } else {
        let temp = format!("{path}.tmp.{}", std::process::id());
        let result = (|| {
            let mut file = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&temp)
                .map_err(|e| e.to_string())?;
            file.write_all(json!({"backend": backend, "networks": nets.iter().map(ToString::to_string).collect::<Vec<_>>()}).to_string().as_bytes()).map_err(|e| e.to_string())?;
            file.sync_all().map_err(|e| e.to_string())?;
            fs::rename(&temp, path).map_err(|e| e.to_string())
        })();
        if result.is_err() {
            let _ = fs::remove_file(temp);
        }
        result?;
    }
    Ok(())
}

fn installed(uid: u32, backend: &str, nets: &[IpNet]) -> Result<bool, String> {
    if nets.is_empty() {
        return Ok(true);
    }
    if backend == "nftables" {
        let table = format!("dropshit_{uid}");
        let text = match command(NFT, &["list", "table", "inet", &table], None) {
            Ok(text) => text,
            Err(_) => return Ok(false),
        };
        // Check the owned table and its hook. Single-address sets omit /32 and /128.
        Ok(text.contains("hook output")
            && text.contains(&format!("skuid {uid}"))
            && text.contains("12000-64000")
            && nets.iter().all(|n| {
                text.contains(&n.to_string())
                    || match n {
                        IpNet::V4(ip) if ip.prefix_len() == 32 => {
                            text.contains(&ip.addr().to_string())
                        }
                        IpNet::V6(ip) if ip.prefix_len() == 128 => {
                            text.contains(&ip.addr().to_string())
                        }
                        _ => false,
                    }
            }))
    } else {
        for family in [4, 6] {
            let selected: Vec<_> = nets
                .iter()
                .filter(|n| n.addr().is_ipv4() == (family == 4))
                .collect();
            if selected.is_empty() {
                continue;
            }
            let (exists, attached, actual) = iptables_snapshot(uid, family)?;
            if !exists || !attached || selected.iter().any(|n| !actual.contains(n)) {
                return Ok(false);
            }
        }
        Ok(true)
    }
}

fn known_uid(state: &str) -> Result<u32, String> {
    let uid = state.parse::<u32>().map_err(|_| "invalid UID")?;
    if uid == 0 || uid == u32::MAX {
        return Err("invalid UID".into());
    }
    Ok(uid)
}

fn lock(uid: u32) -> Result<fs::File, String> {
    let file = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .open(format!("{STATE}/{uid}.lock"))
        .map_err(|e| e.to_string())?;
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) } != 0 {
        return Err(io::Error::last_os_error().to_string());
    }
    Ok(file)
}

fn caller_uid() -> Result<u32, String> {
    let uid = std::env::var("PKEXEC_UID")
        .or_else(|_| std::env::var("SUDO_UID"))
        .map_err(|_| "missing caller UID")?
        .parse::<u32>()
        .map_err(|_| "invalid caller UID")?;
    if uid == 0 || uid == u32::MAX {
        return Err("invalid caller UID".into());
    }
    Ok(uid)
}

pub fn helper() -> Result<(), String> {
    if unsafe { libc::geteuid() } != 0 {
        return Err("helper requires root".into());
    }
    unsafe {
        libc::umask(0o077);
    }
    fs::create_dir_all(STATE).map_err(|e| e.to_string())?;
    let args: Vec<_> = std::env::args().collect();
    if args.len() == 2 && (args[1] == "--restore" || args[1].starts_with("--clear-user=")) {
        if std::env::var_os("PKEXEC_UID").is_some() || std::env::var_os("SUDO_UID").is_some() {
            return Err("administrative commands are root-only".into());
        }
        if let Some(target) = args[1].strip_prefix("--clear-user=") {
            let uid = known_uid(target)?;
            let _held = lock(uid)?;
            if let Some((old_backend, _)) = read_state(uid)? {
                apply(uid, &old_backend, &[])?;
                save(uid, &old_backend, &[])?;
            }
            return Ok(());
        }
        for entry in fs::read_dir(STATE).map_err(|e| e.to_string())? {
            let path = entry.map_err(|e| e.to_string())?.path();
            if path.extension().is_none_or(|ext| ext != "json") {
                continue;
            }
            let Some(uid) = path
                .file_stem()
                .and_then(|n| n.to_str())
                .and_then(|n| known_uid(n).ok())
            else {
                continue;
            };
            let _held = lock(uid)?;
            if let Some((old_backend, nets)) = read_state(uid)? {
                apply(uid, &old_backend, &nets)?;
            }
        }
        return Ok(());
    }
    if args.len() != 1 {
        return Err("invalid helper arguments".into());
    }
    let uid = caller_uid()?;
    let _held = lock(uid)?;
    let mut text = String::new();
    io::stdin()
        .take(MAX_REQUEST + 1)
        .read_to_string(&mut text)
        .map_err(|e| e.to_string())?;
    if text.len() as u64 > MAX_REQUEST {
        return Err("request too large".into());
    }
    let req: Value = serde_json::from_str(&text).map_err(|e| e.to_string())?;
    let (previous_backend, previous) = match read_state(uid)? {
        Some(saved) => saved,
        None => (backend()?.into(), vec![]),
    };
    let response = match req["action"].as_str() {
        Some("status") if req.as_object().is_some_and(|obj| obj.len() == 1) => {
            let active = installed(uid, &previous_backend, &previous)?;
            let chosen = backend()?;
            json!({"backend":previous_backend,"selected_backend":chosen,"networks":previous.iter().map(ToString::to_string).collect::<Vec<_>>(), "active": active})
        }
        Some("apply") if req.as_object().is_some_and(|obj| obj.len() == 2) => {
            let desired = parse_networks(&req["networks"])?;
            let selected = backend()?;
            apply(uid, selected, &desired)?;
            if selected != previous_backend && !previous.is_empty() {
                if let Err(e) = apply(uid, &previous_backend, &[]) {
                    let _ = apply(uid, selected, &[]);
                    return Err(format!("cannot migrate old backend: {e}"));
                }
            }
            if let Err(e) = save(uid, selected, &desired) {
                let _ = apply(uid, &previous_backend, &previous);
                if selected != previous_backend {
                    let _ = apply(uid, selected, &[]);
                }
                return Err(e);
            }
            let active = installed(uid, selected, &desired)?;
            json!({"backend":selected,"networks":desired.iter().map(ToString::to_string).collect::<Vec<_>>(), "active": active})
        }
        _ => return Err("invalid action or request fields".into()),
    };
    println!("{response}");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn limits_networks_and_never_wipes_foreign_tables() {
        assert!(parse_networks(&json!(["0.0.0.0/0"])).is_err());
        let nets = parse_networks(&json!(["34.88.201.2/24", "::1/128"])).unwrap();
        let text = nft_script(1000, &nets);
        assert!(text.contains("34.88.201.0/24"));
        assert!(text.contains("skuid 1000"));
        assert!(!text.contains("flush ruleset"));
        assert!(!text.contains("tcp"));
    }

    #[test]
    fn nft_kernel_rule_lifecycle_in_isolated_user_and_network_namespace() {
        if std::env::var_os("DROPSHIT_KERNEL_TEST").is_none() {
            return;
        }
        let uid = 1000;
        let networks = parse_networks(&json!(["127.0.0.1/32", "::1/128"])).unwrap();
        command(NFT, &["add", "table", "inet", "foreign_table"], None).unwrap();
        nft_apply(uid, &networks).unwrap();
        assert!(
            installed(uid, "nftables", &networks).unwrap(),
            "{}",
            command(
                NFT,
                &["list", "table", "inet", &format!("dropshit_{uid}")],
                None
            )
            .unwrap()
        );
        nft_apply(uid, &[]).unwrap();
        assert!(!installed(uid, "nftables", &networks).unwrap());
        assert!(command(NFT, &["list", "table", "inet", "foreign_table"], None).is_ok());
    }

    #[test]
    fn nft_blocks_only_owned_udp_game_ports_in_namespace() {
        if std::env::var_os("DROPSHIT_KERNEL_PACKET_TEST").is_none() {
            return;
        }
        let uid = unsafe { libc::getuid() };
        let networks = parse_networks(&json!(["127.0.0.1/32", "::1/128"])).unwrap();
        command("/usr/sbin/ip", &["link", "set", "lo", "up"], None).unwrap();
        nft_apply(uid, &networks).unwrap();
        for (host, family) in [("127.0.0.1", false), ("[::1]", true)] {
            for (port, denied) in [
                (11999, false),
                (12000, true),
                (35000, true),
                (64000, true),
                (64001, false),
            ] {
                let sock =
                    std::net::UdpSocket::bind(if family { "[::]:0" } else { "0.0.0.0:0" }).unwrap();
                let result = sock.send_to(&[1], format!("{host}:{port}"));
                assert_eq!(result.is_err(), denied, "{host}:{port}: {result:?}");
            }
            assert!(
                std::net::TcpStream::connect_timeout(
                    &format!("{host}:35000").parse().unwrap(),
                    std::time::Duration::from_millis(100)
                )
                .is_err()
            );
        }
        nft_apply(uid, &[]).unwrap();
    }

    #[test]
    fn iptables_kernel_rule_lifecycle_in_isolated_user_and_network_namespace() {
        if std::env::var_os("DROPSHIT_KERNEL_IPTABLES").is_none() {
            return;
        }
        let uid = 1000;
        let networks = parse_networks(&json!(["127.0.0.1/32", "::1/128"])).unwrap();
        command(tool(4, false), &["-w", "-N", "FOREIGN_DROPSHIT_TEST"], None).unwrap();
        iptables_apply(uid, &networks).unwrap();
        assert!(installed(uid, "iptables", &networks).unwrap());
        let replacement = parse_networks(&json!(["192.0.2.0/24"])).unwrap();
        iptables_apply(uid, &replacement).unwrap();
        assert!(installed(uid, "iptables", &replacement).unwrap());
        iptables_apply(uid, &[]).unwrap();
        assert!(!installed(uid, "iptables", &networks).unwrap());
        assert!(command(tool(4, false), &["-w", "-S", "FOREIGN_DROPSHIT_TEST"], None).is_ok());
    }
}
