use ipnet::IpNet;

// Official Vivox voice-media ranges, reviewed 2026-10-03. Never game blocks.
pub const VIVOX: &[&str] = &["85.236.96.0/21", "85.236.104.0/23"];

pub fn game_networks(networks: &[IpNet]) -> Vec<IpNet> {
    let mut result: Vec<_> = networks.iter().map(IpNet::trunc).collect();
    for text in VIVOX {
        let excluded: IpNet = text.parse().expect("constant Vivox CIDR");
        result = result
            .into_iter()
            .flat_map(|net| subtract(net, excluded))
            .collect();
    }
    result.sort();
    result.dedup();
    let snapshot = result.clone();
    result.retain(|net| {
        !snapshot
            .iter()
            .any(|other| other.prefix_len() < net.prefix_len() && other.contains(&net.addr()))
    });
    result
}

fn subtract(net: IpNet, excluded: IpNet) -> Vec<IpNet> {
    if excluded.contains(&net.addr()) && excluded.prefix_len() <= net.prefix_len() {
        return vec![];
    }
    if !net.contains(&excluded.addr()) {
        return vec![net];
    }
    net.subnets(net.prefix_len() + 1)
        .expect("split enclosing CIDR")
        .flat_map(|part| subtract(part, excluded))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn excludes_voice_hosts_and_supernets_without_losing_neighbor_networks() {
        let nets = game_networks(&["85.236.0.0/16".parse().unwrap(), "::1/128".parse().unwrap()]);
        for (host, allowed) in [
            ("85.236.95.255", true),
            ("85.236.96.0", false),
            ("85.236.97.71", false),
            ("85.236.103.255", false),
            ("85.236.104.0", false),
            ("85.236.105.255", false),
            ("85.236.106.0", true),
            ("::1", true),
        ] {
            assert_eq!(
                nets.iter()
                    .any(|n| n.contains(&host.parse::<std::net::IpAddr>().unwrap())),
                allowed,
                "{host}"
            );
        }
        assert!(game_networks(&["85.236.97.71/32".parse().unwrap()]).is_empty());
        assert_eq!(game_networks(&nets), nets);
    }
}
