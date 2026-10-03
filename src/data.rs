use std::{collections::HashMap, net::IpAddr, process::Command, time::Duration};

use ipnet::IpNet;
use serde_json::Value;

pub const IPS_URL: &str = "https://stowmyy.github.io/dropship/ips.json";
pub const ENDPOINTS_URL: &str = "https://gcping.com/api/endpoints";

// Research-backed candidates; regional evidence/limitations documented separately.
const ADDRESS_SUPPLEMENTS: &[(&str, &str)] =
    &[("ams1", "66.40.191.0/24"), ("ams1", "5.42.168.0/21")];

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
        let mut networks = by_code
            .remove(code)
            .ok_or_else(|| format!("missing region {code}"))?;
        for &(region, cidr) in ADDRESS_SUPPLEMENTS {
            if region == code {
                let net: IpNet = cidr.parse().map_err(|e| format!("{code}: {e}"))?;
                // A smaller feed CIDR must not hide the rest of a supplement.
                if !networks.iter().any(|existing| {
                    existing.prefix_len() <= net.prefix_len() && existing.contains(&net.addr())
                }) {
                    networks.push(net);
                }
            }
        }
        networks = crate::networks::game_networks(&networks);
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

    fn fixtures() -> (Value, Value) {
        let rows: Vec<_> = REGIONS.iter().enumerate().map(|(i, (code, _, _))| {
            serde_json::json!({"token":code,"block":format!("192.0.2.{}/32", i + 1)})
        }).collect();
        let mut endpoints = serde_json::Map::new();
        for key in REGIONS
            .iter()
            .map(|(_, _, key)| *key)
            .chain(["asia-northeast3"])
        {
            endpoints.insert(
                key.into(),
                serde_json::json!({"URL":"https://test.a.run.app"}),
            );
        }
        (
            serde_json::json!({"servers":{"overwatch":rows}}),
            Value::Object(endpoints),
        )
    }

    #[test]
    fn regional_subnets_cover_pool_but_never_vivox() {
        let (mut ips, endpoints) = fixtures();
        ips["servers"]["overwatch"][6]["block"] = "85.236.0.0/16,192.0.2.7/32".into();
        let regions = parse_regions(&ips, &endpoints).unwrap();
        for host in [
            "66.40.191.1",
            "66.40.191.240",
            "66.40.191.254",
            "5.42.168.1",
            "5.42.175.254",
        ] {
            let ip: IpAddr = host.parse().unwrap();
            let matches: Vec<_> = regions
                .iter()
                .filter(|r| r.networks.iter().any(|n| n.contains(&ip)))
                .collect();
            assert_eq!(matches.len(), 1);
            assert_eq!(matches[0].code, "ams1");
        }
        for host in [
            "66.40.190.255",
            "66.40.192.0",
            "5.42.167.255",
            "5.42.176.0",
            "85.236.97.70",
            "85.236.97.72",
            "85.236.104.5",
        ] {
            let ip: IpAddr = host.parse().unwrap();
            assert!(
                regions
                    .iter()
                    .all(|r| r.networks.iter().all(|n| !n.contains(&ip)))
            );
        }
        let flows = "ESTAB 0 0 192.168.1.3:42000 66.40.191.240:26542 users:((\"Overwatch.exe\",pid=1,fd=2))\n\
ESTAB 0 0 192.168.1.3:42001 85.236.97.71:43422 users:((\"Overwatch.exe\",pid=1,fd=3))\n";
        let counts = parse_overwatch_flows(flows, &regions);
        assert_eq!(counts["ams1"], 1);
        assert!(!counts.contains_key("gue4"));
        assert!(!counts.contains_key("gen1"));
    }

    #[test]
    fn narrower_feed_cannot_hide_regional_pool() {
        let (mut ips, endpoints) = fixtures();
        ips["servers"]["overwatch"][0]["block"] = "66.40.191.240/32".into();
        let regions = parse_regions(&ips, &endpoints).unwrap();
        assert_eq!(
            regions[0].networks,
            crate::networks::game_networks(&[
                "66.40.191.0/24".parse().unwrap(),
                "5.42.168.0/21".parse().unwrap()
            ])
        );
    }
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
