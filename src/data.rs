use std::{collections::HashMap, net::IpAddr, process::Command, time::Duration};

use ipnet::IpNet;
use serde_json::Value;

pub const IPS_URL: &str = "https://stowmyy.github.io/dropship/ips.json";
pub const ENDPOINTS_URL: &str = "https://gcping.com/api/endpoints";

pub const REGIONS: &[(&str, &str, &str)] = &[
    ("ams1", "Нидерланды", "europe-west4"),
    ("gbr1", "Бразилия — Сан-Паулу", "southamerica-east1"),
    ("gen1", "Финляндия", "europe-north1"),
    ("gmec2", "Саудовская Аравия", "me-central2"),
    ("gsg1", "Сингапур", "asia-southeast1"),
    ("gtk1", "Япония — Токио", "asia-northeast1"),
    ("gue4", "США — восток", "us-east4"),
    ("las1", "США — юго-запад", "us-west4"),
    ("ord1", "США — центр (Iowa)", "us-central1"),
    ("syd2", "Австралия — Сидней", "australia-southeast1"),
    ("tpe1", "Тайвань", "asia-east1"),
];

#[derive(Clone, Debug)]
pub struct Region {
    pub code: String,
    pub title: String,
    pub url: String,
    pub networks: Vec<IpNet>,
    pub legacy: bool,
}

pub fn fetch_json(url: &str) -> Result<Value, String> {
    let output = Command::new("/usr/bin/curl")
        .args([
            "--fail",
            "--silent",
            "--show-error",
            "--location",
            "--max-time",
            "12",
            "--",
            url,
        ])
        .output()
        .map_err(|e| format!("curl: {e}"))?;
    if !output.status.success() {
        return Err(format!(
            "{}: {}",
            url,
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    serde_json::from_slice(&output.stdout).map_err(|e| format!("{url}: {e}"))
}

pub fn parse_regions(ips: &Value, endpoints: &Value) -> Result<Vec<Region>, String> {
    let rows = ips
        .pointer("/servers/overwatch")
        .and_then(Value::as_array)
        .ok_or("missing servers.overwatch")?;
    let mut by_code = HashMap::new();
    for row in rows {
        let Some(code) = row.get("token").and_then(Value::as_str) else {
            continue;
        };
        let Some(block) = row.get("block").and_then(Value::as_str) else {
            continue;
        };
        let networks: Result<Vec<IpNet>, _> = block.split(',').map(|n| n.trim().parse()).collect();
        let nets = networks.map_err(|e| format!("{code}: invalid network: {e}"))?;
        if nets.is_empty() || nets.iter().any(|n: &IpNet| n.prefix_len() == 0) {
            return Err(format!("{code}: empty network list or default route"));
        }
        by_code.insert(code, nets);
    }
    let mut regions = Vec::new();
    for &(code, title, key) in REGIONS {
        let networks = by_code
            .remove(code)
            .ok_or_else(|| format!("missing region {code}"))?;
        let url = endpoints
            .get(key)
            .and_then(|e| e.get("URL"))
            .and_then(Value::as_str)
            .ok_or_else(|| format!("missing HTTPS endpoint for {key}"))?;
        if !valid_endpoint(url) {
            return Err(format!("invalid HTTPS endpoint for {key}"));
        }
        regions.push(Region {
            code: code.into(),
            title: title.into(),
            url: url.into(),
            networks,
            legacy: false,
        });
    }
    // The Korean location has no current network list; it is never blockable.
    let url = endpoints
        .get("asia-northeast3")
        .and_then(|e| e.get("URL"))
        .and_then(Value::as_str)
        .ok_or("missing Korean HTTPS endpoint")?;
    if !valid_endpoint(url) {
        return Err("invalid Korean HTTPS endpoint".into());
    }
    regions.push(Region {
        code: "icn1".into(),
        title: "Южная Корея (архив)".into(),
        url: url.into(),
        networks: Vec::new(),
        legacy: true,
    });
    Ok(regions)
}

fn valid_endpoint(url: &str) -> bool {
    let Some(host) = url.strip_prefix("https://") else {
        return false;
    };
    let host = host.trim_end_matches('/');
    !host.is_empty()
        && !host.contains(['/', ':', '@', '?', '#'])
        && !host.contains(char::is_whitespace)
        && (host.ends_with(".a.run.app") || host.ends_with(".gcping.com"))
}

/// A single curl process issues four HTTPS requests to the same URL. The first
/// warms up TCP/TLS and the remaining timings are time_total for actual HTTP
/// responses on a connection which curl can reuse. A proxy configured in curl
/// is respected; these numbers are not game-server UDP RTTs.
pub fn measure_https(url: &str) -> Result<Duration, String> {
    let mut cmd = Command::new("/usr/bin/curl");
    cmd.args([
        "--silent",
        "--show-error",
        "--fail",
        "--max-time",
        "8",
        "--connect-timeout",
        "4",
    ]);
    for _ in 0..4 {
        cmd.args([
            "--output",
            "/dev/null",
            "--write-out",
            "%{http_code} %{time_total} %{num_connects}\\n",
            "--url",
            url,
        ]);
    }
    let output = cmd.output().map_err(|e| e.to_string())?;
    if !output.status.success() {
        return Err(String::from_utf8_lossy(&output.stderr).trim().to_owned());
    }
    let text = String::from_utf8_lossy(&output.stdout);
    let lines: Vec<_> = text.lines().collect();
    if lines.len() != 4 {
        return Err(format!("incomplete HTTPS sample: {text}"));
    }
    let values: Vec<f64> = lines
        .into_iter()
        .enumerate()
        .map(|(index, line)| {
            let mut fields = line.split_whitespace();
            let status = fields.next().ok_or("missing HTTP status")?;
            if status != "200" {
                return Err(format!("HTTPS endpoint returned HTTP {status}"));
            }
            let value = fields
                .next()
                .ok_or("missing response time")?
                .parse::<f64>()
                .map_err(|e| e.to_string())?;
            let reused = fields.next().ok_or("missing reuse status")? == "0";
            if index > 0 && !reused {
                return Err("HTTPS connection was not reused".into());
            }
            Ok(value)
        })
        .collect::<Result<_, String>>()?;
    if values.iter().any(|v| !v.is_finite() || *v < 0.0) {
        return Err(format!("incomplete HTTPS sample: {text}"));
    }
    Ok(Duration::from_secs_f64(
        values[1..].iter().sum::<f64>() / 3.0,
    ))
}

pub fn parse_overwatch_flows(text: &str, regions: &[Region]) -> HashMap<String, usize> {
    let mut counts = HashMap::new();
    for line in text.lines() {
        if !line.to_ascii_lowercase().contains("overwatch") {
            continue;
        }
        let Some(peer) = line.split_whitespace().nth(4) else {
            continue;
        };
        let Some((host, port)) = peer.rsplit_once(':') else {
            continue;
        };
        let Ok(port) = port.parse::<u16>() else {
            continue;
        };
        if !(12000..=64000).contains(&port) {
            continue;
        }
        let Ok(ip) = host.trim_matches(['[', ']']).parse::<IpAddr>() else {
            continue;
        };
        for region in regions {
            if region.networks.iter().any(|net| net.contains(&ip)) {
                *counts.entry(region.code.clone()).or_insert(0) += 1;
            }
        }
    }
    counts
}

pub fn observe_udp(regions: &[Region]) -> HashMap<String, usize> {
    let Ok(output) = Command::new("/usr/bin/ss")
        .args(["-H", "-n", "-u", "-p"])
        .output()
    else {
        return HashMap::new();
    };
    if !output.status.success() {
        return HashMap::new();
    }
    parse_overwatch_flows(&String::from_utf8_lossy(&output.stdout), regions)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejects_missing_region_without_inventing_game_addresses() {
        let endpoints = serde_json::json!({});
        assert!(
            parse_regions(&serde_json::json!({"servers":{"overwatch":[]}}), &endpoints).is_err()
        );
    }

    #[test]
    fn observes_only_overwatch_owned_udp_flows_in_game_network() {
        let region = Region {
            code: "gen1".into(),
            title: "Finland".into(),
            url: String::new(),
            networks: vec!["34.88.0.0/16".parse().unwrap()],
            legacy: false,
        };
        let sample = "ESTAB 0 0 192.168.1.3:42000 34.88.201.2:26542 users:((\"Overwatch.exe\",pid=1,fd=2))\n\
ESTAB 0 0 192.168.1.3:42001 34.88.201.2:26542 users:((\"curl\",pid=1,fd=2))\n\
ESTAB 0 0 192.168.1.3:42002 85.236.97.61:43422 users:((\"Overwatch.exe\",pid=1,fd=2))\n";
        assert_eq!(parse_overwatch_flows(sample, &[region])["gen1"], 1);
    }

    #[test]
    #[ignore = "requires external HTTPS endpoint"]
    fn regional_https_connection_is_reused() {
        let endpoints = fetch_json(ENDPOINTS_URL).unwrap();
        let url = endpoints["europe-north1"]["URL"].as_str().unwrap();
        assert!(measure_https(url).unwrap().as_millis() > 0);
    }
}
