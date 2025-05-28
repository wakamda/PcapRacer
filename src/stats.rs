use std::collections::HashMap;
use std::collections::HashSet;
use std::net::Ipv4Addr;

#[derive(Default, Debug,Clone)]
pub struct FlowStat {
    pub total_pkts: u64,
    pub total_bytes: u64,
    pub up_pkts: u64,
    pub up_bytes: u64,
    pub down_pkts: u64,
    pub down_bytes: u64,
}

pub fn find_local_ip(lines: &[String]) -> Result<String, String> {
    let mut lan_ips = HashSet::new();

    for line in lines {
        let cols: Vec<&str> = line.split('\t').collect();
        if cols.len() < 3 {
            continue;
        }
        for ip_str in &[cols[0], cols[1]] {
            if let Ok(ipv4) = ip_str.parse::<Ipv4Addr>() {
                if is_lan_ip(&ipv4) && !is_non_host_ip(&ipv4) && *ip_str != "0.0.0.0" {
                    lan_ips.insert(ip_str.to_string());
                }
            }
        }
    }

    match lan_ips.len() {
        0 => Err("未找到局域网 IP".to_string()),
        1 => Ok(lan_ips.into_iter().next().unwrap()),
        _ => {
            eprintln!("发现多个局域网 IP，无法自动判断本地 IP：");
            for ip in &lan_ips {
                eprintln!("  - {}", ip);
            }
            Err("局域网 IP 不唯一".to_string())
        }
    }
}

fn is_lan_ip(ip: &Ipv4Addr) -> bool {
    ip.is_private()
}

fn is_non_host_ip(ip: &Ipv4Addr) -> bool {
    let last_octet = ip.octets()[3];
    last_octet == 1 || last_octet == 255
}


pub fn aggregate_with_local_ip(
    lines: &[String],
    local_ip: &str,
) -> HashMap<String, FlowStat> {
    let mut stats: HashMap<String, FlowStat> = HashMap::new();

    for line in lines {
        let cols: Vec<&str> = line.split('\t').collect();
        if cols.len() < 3 {
            continue;
        }
        let src = cols[0];
        let dst = cols[1];
        let len: u64 = cols[2].parse().unwrap_or(0);

        if src == local_ip {
            let entry = stats.entry(dst.to_string()).or_default();
            entry.total_pkts += 1;
            entry.total_bytes += len;
            entry.up_pkts += 1;
            entry.up_bytes += len;
        } else if dst == local_ip {
            let entry = stats.entry(src.to_string()).or_default();
            entry.total_pkts += 1;
            entry.total_bytes += len;
            entry.down_pkts += 1;
            entry.down_bytes += len;
        }
    }
    stats
}
