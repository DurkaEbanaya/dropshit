//! Privileged, per-UID firewall rules. This module is only compiled into the helper.
use std::{
    fs,
    io::{self, BufRead, Read, Write},
    os::{fd::AsRawFd, unix::fs::OpenOptionsExt},
    path::Path,
    process::{Command, Stdio},
};

use crate::networks::Policy;
use ipnet::IpNet;
use serde_json::{Value, json};

const STATE: &str = "/var/lib/dropshit";
const NFT: &str = "/usr/sbin/nft";
const MAX_REQUEST: u64 = 262_144;
// Game-port window minus the user-requested Discord media destination ports.
// 1541 is already outside the window; 50000–50032 is inside 50000–65535.
const FILTERED_PORTS: &[(u16, u16)] = &[(12000, 19293), (19345, 49999)];
const DISCORD_PORTS: &str = "1541,19294:19344,50000:65535";

fn discord_return(chain: &str) -> String {
    format!("-A {chain} -p udp -m multiport --dports {DISCORD_PORTS} -j RETURN")
}

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
            for (first, last) in FILTERED_PORTS {
                text += &format!(
                    "meta skuid {uid} {family} daddr @{name} udp dport {first}-{last} reject\n"
                );
            }
        }
    }
    text + "}\n}\n"
}

fn nft_apply(uid: u32, networks: &[IpNet]) -> Result<(), String> {
    command(NFT, &["-f", "-"], Some(&nft_script(uid, networks))).map(|_| ())
}

fn tool(family: u8, restore: bool) -> &'static str {
    #[cfg(test)]
    if std::env::var_os("DROPSHIT_KERNEL_IPTABLES").is_some()
        && Path::new("/tmp/opencode/dropshit-iptables/usr/sbin/iptables-nft").exists()
    {
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

fn iptables_snapshot(uid: u32, family: u8) -> Result<(bool, bool, Vec<IpNet>, bool), String> {
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
    let mut protected = false;
    for line in output
        .lines()
        .filter(|line| line.starts_with(&format!("-A {chain} ")))
    {
        if line == discord_return(&chain) && nets.is_empty() && !protected {
            protected = true;
            continue;
        }
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
    Ok((exists, attached, nets, protected))
}

fn iptables_write(
    uid: u32,
    family: u8,
    networks: &[IpNet],
    existed: bool,
    attached: bool,
    protect_discord: bool,
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
        if protect_discord {
            lines.push(discord_return(&chain));
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
    iptables_write(uid, 4, &new4, old4.0, old4.1, true)?;
    if let Err(error) = iptables_write(uid, 6, &new6, old6.0, old6.1, true) {
        let current4 = iptables_snapshot(uid, 4)?;
        iptables_write(uid, 4, &old4.2, current4.0, current4.1, old4.3)
            .map_err(|rollback| format!("{error}; IPv4 rollback FAILED: {rollback}"))?;
        return Err(error);
    }
    Ok(())
}

fn apply(uid: u32, backend: &str, networks: &[IpNet]) -> Result<(), String> {
    let protected = crate::networks::game_networks(networks);
    let networks = protected.as_slice();
    match backend {
        "nftables" => nft_apply(uid, networks),
        "iptables" => iptables_apply(uid, networks),
        _ => Err("invalid backend".into()),
    }
}

fn state_path(uid: u32) -> String {
    format!("{STATE}/{uid}.json")
}

fn parse_policy(value: &Value) -> Result<Policy, String> {
    let strict = match value["mode"].as_str() {
        None if value.get("mode").is_none() => false,
        Some("blocklist") => false,
        Some("allowlist") => true,
        _ => return Err("invalid policy mode".into()),
    };
    let region = match value.get("region") {
        None | Some(Value::Null) => None,
        Some(Value::String(s))
            if !s.is_empty() && s.len() <= 32 && s.bytes().all(|c| c.is_ascii_alphanumeric()) =>
        {
            Some(s.clone())
        }
        _ => return Err("invalid region code".into()),
    };
    let nets = parse_networks(&value["networks"])?;
    if strict && (region.is_none() || nets.is_empty()) {
        return Err("allowlist requires a region and nonempty networks".into());
    }
    if !strict && region.is_some() {
        return Err("blocklist has no single allowed region".into());
    }
    Ok(Policy {
        strict,
        region,
        networks: nets,
    })
}

fn apply_policy(uid: u32, backend: &str, policy: &Policy) -> Result<(), String> {
    apply(uid, backend, &policy.blocked_networks())
}

fn policy_reply(backend: &str, chosen: &str, policy: &Policy, active: bool) -> Value {
    json!({"backend":backend,"selected_backend":chosen,"mode":policy.mode(),"region":policy.region,
        "networks":policy.networks.iter().map(ToString::to_string).collect::<Vec<_>>(),"active":active})
}

fn read_state(uid: u32) -> Result<Option<(String, Policy)>, String> {
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
    Ok(Some((backend.into(), parse_policy(&value)?)))
}

fn save(uid: u32, backend: &str, policy: &Policy) -> Result<(), String> {
    let path = state_path(uid);
    if !policy.strict && policy.networks.is_empty() {
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
            file.write_all(
                policy_reply(backend, backend, policy, true)
                    .to_string()
                    .as_bytes(),
            )
            .map_err(|e| e.to_string())?;
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

fn ip_number(ip: std::net::IpAddr) -> u128 {
    match ip {
        std::net::IpAddr::V4(ip) => u32::from(ip) as u128,
        std::net::IpAddr::V6(ip) => u128::from(ip),
    }
}

fn net_interval(net: &IpNet) -> (u128, u128) {
    (ip_number(net.network()), ip_number(net.broadcast()))
}

fn merge_intervals(mut ranges: Vec<(u128, u128)>) -> Vec<(u128, u128)> {
    ranges.sort();
    let mut merged: Vec<(u128, u128)> = Vec::new();
    for (start, end) in ranges {
        if let Some(last) = merged.last_mut()
            && start <= last.1.saturating_add(1)
        {
            last.1 = last.1.max(end);
        } else {
            merged.push((start, end));
        }
    }
    merged
}

fn nft_element_interval(value: &Value, v4: bool) -> Option<(u128, u128)> {
    let address = |value: &Value| -> Option<std::net::IpAddr> {
        let ip: std::net::IpAddr = value.as_str()?.parse().ok()?;
        (ip.is_ipv4() == v4).then_some(ip)
    };
    if let Some(prefix) = value.get("prefix") {
        let ip = address(&prefix["addr"])?;
        let len = u8::try_from(prefix["len"].as_u64()?).ok()?;
        return Some(net_interval(&IpNet::new(ip, len).ok()?));
    }
    if let Some(range) = value.get("range").and_then(Value::as_array) {
        if range.len() != 2 {
            return None;
        }
        let start = ip_number(address(&range[0])?);
        let end = ip_number(address(&range[1])?);
        return (start <= end).then_some((start, end));
    }
    let ip = ip_number(address(value)?);
    Some((ip, ip))
}

fn nft_installed_json(uid: u32, nets: &[IpNet], document: &Value) -> bool {
    let Some(objects) = document["nftables"].as_array() else {
        return false;
    };
    let table = format!("dropshit_{uid}");
    let owned = |obj: &Value| obj["family"] == "inet" && obj["table"] == table;
    if !objects.iter().any(|obj| {
        let chain = &obj["chain"];
        owned(chain)
            && chain["name"] == "output"
            && chain["type"] == "filter"
            && chain["hook"] == "output"
            && chain["prio"] == -10
            && chain["policy"] == "accept"
    }) {
        return false;
    }
    // No extra rule may continue rejecting Discord after the corrected rules.
    let expected_rules = FILTERED_PORTS.len()
        * [true, false]
            .iter()
            .filter(|v4| nets.iter().any(|n| n.addr().is_ipv4() == **v4))
            .count();
    if objects
        .iter()
        .filter(|obj| owned(&obj["rule"]) && obj["rule"]["chain"] == "output")
        .count()
        != expected_rules
    {
        return false;
    }
    for (v4, name, kind, protocol) in [
        (true, "blocked4", "ipv4_addr", "ip"),
        (false, "blocked6", "ipv6_addr", "ip6"),
    ] {
        let wanted = merge_intervals(
            nets.iter()
                .filter(|n| n.addr().is_ipv4() == v4)
                .map(net_interval)
                .collect(),
        );
        if wanted.is_empty() {
            continue;
        }
        let Some(set) = objects
            .iter()
            .map(|obj| &obj["set"])
            .find(|s| owned(s) && s["name"] == name && s["type"] == kind)
        else {
            return false;
        };
        let Some(elements) = set["elem"].as_array() else {
            return false;
        };
        let Some(actual) = elements
            .iter()
            .map(|e| nft_element_interval(e, v4))
            .collect::<Option<Vec<_>>>()
        else {
            return false;
        };
        if merge_intervals(actual) != wanted {
            return false;
        }
        for (first, last) in FILTERED_PORTS {
            let expected = json!([
                {"match":{"op":"==","left":{"meta":{"key":"skuid"}},"right":uid}},
                {"match":{"op":"==","left":{"payload":{"protocol":protocol,"field":"daddr"}},"right":format!("@{name}")}},
                {"match":{"op":"==","left":{"payload":{"protocol":"udp","field":"dport"}},"right":{"range":[first,last]}}}
            ]);
            if !objects.iter().any(|obj| {
                let rule = &obj["rule"];
                owned(rule)
                    && rule["chain"] == "output"
                    && rule["expr"].as_array().is_some_and(|expr| {
                        expr.len() == 4
                            && expr[..3] == expected.as_array().unwrap()[..]
                            && expr[3].get("reject").is_some()
                    })
            }) {
                return false;
            }
        }
    }
    true
}

fn installed(uid: u32, backend: &str, nets: &[IpNet]) -> Result<bool, String> {
    if nets.is_empty() {
        return Ok(true);
    }
    if backend == "nftables" {
        let table = format!("dropshit_{uid}");
        let text = match command(NFT, &["-j", "list", "table", "inet", &table], None) {
            Ok(text) => text,
            Err(_) => return Ok(false),
        };
        let document: Value =
            serde_json::from_str(&text).map_err(|e| format!("invalid nft JSON: {e}"))?;
        Ok(nft_installed_json(uid, nets, &document))
    } else {
        for family in [4, 6] {
            let selected: Vec<_> = nets
                .iter()
                .filter(|n| n.addr().is_ipv4() == (family == 4))
                .collect();
            if selected.is_empty() {
                continue;
            }
            let (exists, attached, actual, protected) = iptables_snapshot(uid, family)?;
            if !exists || !attached || !protected || selected.iter().any(|n| !actual.contains(n)) {
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
                save(uid, &old_backend, &Policy::default())?;
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
            if let Some((old_backend, policy)) = read_state(uid)? {
                let cleaned = Policy {
                    networks: crate::networks::game_networks(&policy.networks),
                    ..policy.clone()
                };
                apply_policy(uid, &old_backend, &cleaned)?;
                if cleaned != policy {
                    save(uid, &old_backend, &cleaned)?;
                }
            }
        }
        return Ok(());
    }
    if args.len() == 2 && args[1] == "--session" {
        let uid = caller_uid()?;
        let mut input = io::stdin().lock();
        loop {
            let mut line = String::new();
            let size = (&mut input)
                .take(MAX_REQUEST + 1)
                .read_line(&mut line)
                .map_err(|e| e.to_string())?;
            if size == 0 {
                return Ok(());
            }
            if size as u64 > MAX_REQUEST {
                return Err("request too large".into());
            }
            match handle_request(uid, &line) {
                Ok(reply) => println!("{reply}"),
                Err(e) => println!("{}", json!({"error":e})),
            }
            io::stdout().flush().map_err(|e| e.to_string())?;
        }
    }
    if args.len() != 1 {
        return Err("invalid helper arguments".into());
    }
    let uid = caller_uid()?;
    let mut text = String::new();
    io::stdin()
        .take(MAX_REQUEST + 1)
        .read_to_string(&mut text)
        .map_err(|e| e.to_string())?;
    if text.len() as u64 > MAX_REQUEST {
        return Err("request too large".into());
    }
    println!("{}", handle_request(uid, &text)?);
    Ok(())
}

fn handle_request(uid: u32, text: &str) -> Result<Value, String> {
    let _held = lock(uid)?;
    let req: Value = serde_json::from_str(text).map_err(|e| e.to_string())?;
    let valid = match req["action"].as_str() {
        Some("status") => req.as_object().is_some_and(|obj| obj.len() == 1),
        Some("apply") => req.as_object().is_some_and(|obj| {
            obj.contains_key("networks")
                && obj
                    .keys()
                    .all(|k| ["action", "networks", "mode", "region"].contains(&k.as_str()))
        }),
        _ => false,
    };
    if !valid {
        return Err("invalid action or request fields".into());
    }
    if req["action"] == "apply" {
        parse_policy(&req)?;
    }
    let (previous_backend, mut previous) = match read_state(uid)? {
        Some(saved) => saved,
        None => (backend()?.into(), Policy::default()),
    };
    // Migrate saved voice blocks on the first authenticated check as well as boot.
    let cleaned = Policy {
        networks: crate::networks::game_networks(&previous.networks),
        ..previous.clone()
    };
    if cleaned != previous {
        apply_policy(uid, &previous_backend, &cleaned)?;
        save(uid, &previous_backend, &cleaned)?;
        previous = cleaned;
    }
    let response = match req["action"].as_str() {
        Some("status") if req.as_object().is_some_and(|obj| obj.len() == 1) => {
            let active = installed(uid, &previous_backend, &previous.blocked_networks())?;
            let chosen = backend()?;
            policy_reply(&previous_backend, chosen, &previous, active)
        }
        Some("apply") => {
            let mut desired = parse_policy(&req)?;
            desired.networks = crate::networks::game_networks(&desired.networks);
            if desired.strict && desired.networks.is_empty() {
                return Err("allowlist has no game networks".into());
            }
            let selected = backend()?;
            apply_policy(uid, selected, &desired)?;
            if selected != previous_backend && (previous.strict || !previous.networks.is_empty()) {
                if let Err(e) = apply(uid, &previous_backend, &[]) {
                    let _ = apply(uid, selected, &[]);
                    return Err(format!("cannot migrate old backend: {e}"));
                }
            }
            if let Err(e) = save(uid, selected, &desired) {
                let _ = apply_policy(uid, &previous_backend, &previous);
                if selected != previous_backend {
                    let _ = apply(uid, selected, &[]);
                }
                return Err(e);
            }
            let active = installed(uid, selected, &desired.blocked_networks())?;
            policy_reply(selected, selected, &desired, active)
        }
        _ => return Err("invalid action or request fields".into()),
    };
    Ok(response)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn policy_state_is_backward_compatible_and_strict_mode_roundtrips() {
        let old = parse_policy(&json!({"backend":"nftables","networks":["192.0.2.0/24"]})).unwrap();
        assert!(!old.strict);
        let policy = Policy {
            strict: true,
            region: Some("gen1".into()),
            networks: vec!["34.88.0.0/16".parse().unwrap()],
        };
        assert_eq!(
            parse_policy(&policy_reply("nftables", "nftables", &policy, true)).unwrap(),
            policy
        );
        assert!(parse_policy(&json!({"mode":"allowlist","region":"gen1","networks":[]})).is_err());
        assert!(parse_policy(&json!({"mode":"bad","networks":[]})).is_err());
    }

    #[test]
    fn strict_policy_packets_switch_restore_and_clear() {
        let iptables = std::env::var_os("DROPSHIT_KERNEL_IPTABLES").is_some();
        if !iptables && std::env::var_os("DROPSHIT_KERNEL_PACKET_TEST").is_none() {
            return;
        }
        let backend = if iptables { "iptables" } else { "nftables" };
        let uid = unsafe { libc::getuid() };
        command("/usr/sbin/ip", &["link", "set", "lo", "up"], None).unwrap();
        let hosts = [
            "34.88.201.2",
            "85.236.97.71",
            "85.236.104.1",
            "137.221.86.97",
            "192.0.2.1",
            "2600:1900:4150::1",
            "2001:db8::1",
        ];
        for host in hosts {
            let suffix = if host.contains(':') { 128 } else { 32 };
            command(
                "/usr/sbin/ip",
                &["addr", "add", &format!("{host}/{suffix}"), "dev", "lo"],
                None,
            )
            .unwrap();
        }
        let strict = Policy {
            strict: true,
            region: Some("gen1".into()),
            networks: vec![
                "34.88.0.0/16".parse().unwrap(),
                "2600:1900:4150::/44".parse().unwrap(),
            ],
        };
        command(NFT, &["add", "table", "inet", "foreign_strict_test"], None).unwrap();
        for iteration in 0..4 {
            let policy = match iteration {
                0 | 2 => strict.clone(),
                1 => Policy {
                    networks: vec!["137.221.86.0/24".parse().unwrap()],
                    ..Policy::default()
                },
                _ => Policy::default(),
            };
            let restored = parse_policy(&policy_reply(backend, backend, &policy, true)).unwrap();
            apply_policy(uid, backend, &restored).unwrap();
            if iteration == 0 {
                // Simulate 0.1.5 rules with no Discord exception, then upgrade.
                if iptables {
                    let rule = discord_return(&format!("DSHT_{uid}")).replacen("-A ", "-D ", 1);
                    let args: Vec<_> = rule.split_whitespace().collect();
                    for family in [4, 6] {
                        command(tool(family, false), &args, None).unwrap();
                    }
                } else {
                    let legacy = nft_script(uid, &policy.blocked_networks())
                        .replace("12000-19293", "12000-64000")
                        .replace("19345-49999", "12000-64000");
                    command(NFT, &["-f", "-"], Some(&legacy)).unwrap();
                }
                assert!(!installed(uid, backend, &policy.blocked_networks()).unwrap());
                apply_policy(uid, backend, &restored).unwrap();
            }
            assert!(installed(uid, backend, &policy.blocked_networks()).unwrap());
            for (index, host) in hosts.iter().enumerate() {
                let denied = if policy.strict {
                    [3, 4, 6].contains(&index)
                } else {
                    iteration == 1 && index == 3
                };
                for port in [
                    1541, 11999, 12000, 19293, 19294, 19344, 19345, 29503, 43422, 49999, 50000,
                    50032, 50033, 64000, 64001, 65535,
                ] {
                    let target = if host.contains(':') {
                        format!("[{host}]:{port}")
                    } else {
                        format!("{host}:{port}")
                    };
                    let listener = std::net::UdpSocket::bind(&target).unwrap();
                    listener
                        .set_read_timeout(Some(std::time::Duration::from_millis(50)))
                        .unwrap();
                    let socket = std::net::UdpSocket::bind(if host.contains(':') {
                        "[::]:0"
                    } else {
                        "0.0.0.0:0"
                    })
                    .unwrap();
                    let reject =
                        denied && matches!(port, 12000 | 19293 | 19345 | 29503 | 43422 | 49999);
                    assert_eq!(
                        socket.send_to(&[1], &target).is_err(),
                        reject,
                        "{iteration}: {target}"
                    );
                    let mut buf = [0];
                    assert_eq!(
                        listener.recv(&mut buf).is_ok(),
                        !reject,
                        "delivery {target}"
                    );
                }
                let addr = if host.contains(':') {
                    format!("[{host}]:443")
                } else {
                    format!("{host}:443")
                };
                let listener = std::net::TcpListener::bind(&addr).unwrap();
                assert!(
                    std::net::TcpStream::connect_timeout(
                        &addr.parse().unwrap(),
                        std::time::Duration::from_millis(200)
                    )
                    .is_ok()
                );
                drop(listener);
            }
        }
        assert!(command(NFT, &["list", "table", "inet", "foreign_strict_test"], None).is_ok());
    }
    #[test]
    fn interval_comparison_preserves_holes_and_full_ipv6_range() {
        assert_eq!(
            merge_intervals(vec![(10, 20), (21, 30), (12, 15)]),
            vec![(10, 30)]
        );
        assert_eq!(
            merge_intervals(vec![(10, 20), (22, 30)]),
            vec![(10, 20), (22, 30)]
        );
        assert_eq!(
            merge_intervals(vec![(0, u128::MAX), (u128::MAX, u128::MAX)]),
            vec![(0, u128::MAX)]
        );
        assert_eq!(
            nft_element_interval(&json!({"range":["34.84.0.0","34.87.191.255"]}), true),
            Some((
                ip_number("34.84.0.0".parse().unwrap()),
                ip_number("34.87.191.255".parse().unwrap())
            ))
        );
        assert!(nft_element_interval(&json!({"range":["::1","::2"]}), true).is_none());
    }
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
        let networks = parse_networks(&json!([
            "127.0.0.1/32",
            "::1/128",
            "5.42.160.0/22",
            "5.42.164.0/22",
            "5.42.168.0/21",
            "34.84.0.0/16",
            "34.85.0.0/16",
            "34.86.0.0/16",
            "34.87.0.0/17",
            "34.87.128.0/18",
            "2600:1900:4080::/44",
            "2600:1900:4090::/44"
        ]))
        .unwrap();
        command(NFT, &["add", "table", "inet", "foreign_table"], None).unwrap();
        nft_apply(uid, &networks).unwrap();
        let text = command(
            NFT,
            &["-j", "list", "table", "inet", &format!("dropshit_{uid}")],
            None,
        )
        .unwrap();
        let document: Value = serde_json::from_str(&text).unwrap();
        assert!(nft_installed_json(uid, &networks, &document));
        for fault in [
            "missing-set",
            "wrong-uid",
            "missing-hook",
            "accept-instead-of-reject",
            "legacy-ports",
            "extra-legacy-rule",
            "missing-address",
        ] {
            let mut broken = document.clone();
            if fault == "extra-legacy-rule" {
                let mut rule = broken["nftables"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .find(|o| o.get("rule").is_some())
                    .unwrap()
                    .clone();
                rule["rule"]["expr"][2]["match"]["right"] = json!({"range":[12000,64000]});
                broken["nftables"].as_array_mut().unwrap().push(rule);
            }
            for obj in broken["nftables"].as_array_mut().unwrap() {
                if obj.get("set").is_some() && obj["set"]["name"] == "blocked4" {
                    if fault == "missing-set" {
                        obj["set"]["name"] = "other".into();
                    }
                    if fault == "missing-address" {
                        obj["set"]["elem"].as_array_mut().unwrap().pop();
                    }
                }
                if obj.get("chain").is_some() && fault == "missing-hook" {
                    obj["chain"]["hook"] = "input".into();
                }
                if obj.get("rule").is_some() {
                    if fault == "legacy-ports" {
                        obj["rule"]["expr"][2]["match"]["right"] = json!({"range":[12000,64000]});
                    }
                    if fault == "wrong-uid" {
                        obj["rule"]["expr"][0]["match"]["right"] = 1001.into();
                    }
                    if fault == "accept-instead-of-reject" {
                        obj["rule"]["expr"][3] = json!({"accept":null});
                    }
                }
            }
            assert!(!nft_installed_json(uid, &networks, &broken), "{fault}");
        }
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
                (19294, false),
                (19344, false),
                (50000, false),
                (64000, false),
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
    fn regional_subnets_block_pool_and_migrate_voice_blocks() {
        let iptables = std::env::var_os("DROPSHIT_KERNEL_IPTABLES").is_some();
        if !iptables && std::env::var_os("DROPSHIT_KERNEL_PACKET_TEST").is_none() {
            return;
        }
        let uid = unsafe { libc::getuid() };
        command("/usr/sbin/ip", &["link", "set", "lo", "up"], None).unwrap();
        for host in [
            "66.40.191.240",
            "66.40.191.241",
            "66.40.190.241",
            "5.42.175.1",
            "5.42.176.1",
            "85.236.97.71",
            "85.236.104.1",
        ] {
            command(
                "/usr/sbin/ip",
                &["addr", "add", &format!("{host}/32"), "dev", "lo"],
                None,
            )
            .unwrap();
        }
        let old = parse_networks(&json!(["85.236.97.71/32"])).unwrap();
        let backend = if iptables { "iptables" } else { "nftables" };
        if iptables {
            iptables_apply(uid, &old).unwrap();
        } else {
            nft_apply(uid, &old).unwrap();
        }
        let nets = parse_networks(&json!([
            "66.40.191.0/24",
            "5.42.168.0/21",
            "85.236.96.0/21",
            "85.236.104.0/23"
        ]))
        .unwrap();
        apply(uid, backend, &nets).unwrap();
        let cleaned = crate::networks::game_networks(&nets);
        assert!(installed(uid, backend, &cleaned).unwrap());
        for (host, blocked) in [
            ("66.40.191.240", true),
            ("66.40.191.241", true),
            ("66.40.190.241", false),
            ("5.42.175.1", true),
            ("5.42.176.1", false),
            ("85.236.97.71", false),
            ("85.236.104.1", false),
        ] {
            for port in [11999, 26542, 43422, 64001] {
                let socket = std::net::UdpSocket::bind("0.0.0.0:0").unwrap();
                assert_eq!(
                    socket.send_to(&[1], format!("{host}:{port}")).is_err(),
                    blocked && (12000..=64000).contains(&port)
                );
            }
        }
        apply(uid, backend, &[]).unwrap();
    }

    #[test]
    fn iptables_kernel_rule_lifecycle_in_isolated_user_and_network_namespace() {
        if std::env::var_os("DROPSHIT_KERNEL_IPTABLES").is_none() {
            return;
        }
        let uid = 1000;
        let networks = parse_networks(&json!([
            "127.0.0.1/32",
            "::1/128",
            "66.40.191.240/32",
            "85.236.97.71/32"
        ]))
        .unwrap();
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
