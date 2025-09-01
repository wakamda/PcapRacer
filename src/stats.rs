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
    pub domains: HashSet<String>,
}

pub fn find_local_ip(lines: &[String]) -> Result<String, String> {
    let mut ip_counts: HashMap<String, usize> = HashMap::new();
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
                    *ip_counts.entry(ip_str.to_string()).or_insert(0) += 1;
                }
            }
        }
    }

    match lan_ips.len() {
        0 => Err("❌ 未找到局域网 IP".to_string()),
        1 => Ok(lan_ips.into_iter().next().unwrap()),
        _ => {
            // 过滤只包含局域网 IP 的统计信息
            let mut sorted_ips: Vec<(String, usize)> = ip_counts
                .into_iter()
                .filter(|(ip, _)| lan_ips.contains(ip))
                .collect();

            // 按出现次数从多到少排序
            sorted_ips.sort_by(|a, b| b.1.cmp(&a.1));
            
            // // debug 输出局域网 IP 及其出现次数
            // println!("局域网 IP 出现次数 Top 5：");
            // for (ip, count) in sorted_ips.iter().take(5) {
            //     println!("  - {:<15} 次数: {}", ip, count);
            // }

            // 判断最大值是否唯一
            let top_count = sorted_ips[0].1;
            let top_ips: Vec<&(String, usize)> = sorted_ips
                .iter()
                .filter(|(_, count)| *count == top_count)
                .collect();

            if top_ips.len() == 1 {
                Ok(top_ips[0].0.clone())
            } else {
                Err("❌ 局域网 IP 不唯一，无法自动选择".to_string())
            }
        }
    }
}

fn is_lan_ip(ip: &Ipv4Addr) -> bool {
    ip.octets()[0] == 10 ||
    (ip.octets()[0] == 172 && (16..=31).contains(&ip.octets()[1])) ||
    (ip.octets()[0] == 192 && ip.octets()[1] == 168)
}

fn is_non_host_ip(ip: &Ipv4Addr) -> bool {
    ip.is_loopback() || ip.is_link_local() || ip.is_broadcast() || ip.is_multicast()
}

fn insert_domain_field(entry: &mut FlowStat, field: &str) {
    if field.is_empty() {
        return;
    }
    // 按逗号拆分，去除空白
    let parts: Vec<_> = field
        .split(',')
        .map(|d| d.trim())
        .filter(|d| !d.is_empty())
        .collect();

    if parts.is_empty() {
        return;
    }
    // 如果全部相同，只插入一个
    if parts.iter().all(|d| d == &parts[0]) {
        entry.domains.insert(parts[0].to_string());
    } else {
        for domain in parts {
            entry.domains.insert(domain.to_string());
        }
    }
}

pub fn aggregate_with_local_ip(
    lines: &[String],
    local_ip: &str,
    company: Option<&str>,
) -> (HashMap<String, FlowStat>, u64, u64, u64) {
    let mut stats: HashMap<String, FlowStat> = HashMap::new();

    let mut all_total_bytes: u64 = 0;
    let mut all_total_up: u64 = 0;
    let mut all_total_down: u64 = 0;

    for (line_num, line) in lines.iter().enumerate() {
        let cols: Vec<&str> = line.split('\t').collect();
        if cols.len() < 3 {
            eprintln!("第 {} 行格式错误，跳过: {:?}", line_num + 1, line);
            continue;
        }
        let src = cols[0];
        let dst = cols[1];

        if src.trim().is_empty() || dst.trim().is_empty() {
            // eprintln!("第 {} 行空 IP，跳过：src='{}', dst='{}'", line_num + 1, src, dst);
            continue;
        }

        let src_ip = match src.parse::<Ipv4Addr>() {
            Ok(ip) => ip,
            Err(e) => {
                eprintln!("第 {} 行无法解析 src [{}]: {}", line_num + 1, src, e);
                continue;
            }
        };

        let dst_ip = match dst.parse::<Ipv4Addr>() {
            Ok(ip) => ip,
            Err(e) => {
                eprintln!("第 {} 行无法解析 dst [{}]: {}", line_num + 1, dst, e);
                continue;
            }
        };

        // 过滤网关 IP
        if src_ip.octets()[3] == 1 || dst_ip.octets()[3] == 1 {
            continue;
        }

        if is_lan_ip(&src_ip) && is_lan_ip(&dst_ip) {
            continue;
        }
    
        // 过滤非主机 IP（环回、广播、多播等）
        if is_non_host_ip(&src_ip) || is_non_host_ip(&dst_ip) {
            continue;
        }

        let len: u64 = cols[2].parse().unwrap_or(0);

        // 提取域名字段（后面可能为空）
        let dns_name = cols.get(3).unwrap_or(&"").trim();
        let http_host = cols.get(4).unwrap_or(&"").trim();
        let ssl_sni = cols.get(5).unwrap_or(&"").trim();

        if src == local_ip {
            let entry = stats.entry(dst.to_string()).or_default();
            entry.total_pkts += 1;
            entry.total_bytes += len;
            entry.up_pkts += 1;
            entry.up_bytes += len;

            insert_domain_field(entry, dns_name);
            insert_domain_field(entry, http_host);
            insert_domain_field(entry, ssl_sni);

            // 累计总流量
            all_total_bytes += len;
            all_total_up += len;
        } else if dst == local_ip {
            let entry = stats.entry(src.to_string()).or_default();
            entry.total_pkts += 1;
            entry.total_bytes += len;
            entry.down_pkts += 1;
            entry.down_bytes += len;

            insert_domain_field(entry, dns_name);
            insert_domain_field(entry, http_host);
            insert_domain_field(entry, ssl_sni);

            // 累计总流量
            all_total_bytes += len;
            all_total_down += len;
        }
    }

    // 过滤掉 total_bytes 小于 1024 的项
    stats.retain(|_, stat| stat.total_bytes >= 1024);

    // 最后再根据公司关键字过滤
    if let Some(keyword) = company {
        let keyword_lower = keyword.to_lowercase();
        stats.retain(|_ip, stat| {
            stat.domains.iter()
                .any(|domain| domain.to_lowercase().contains(&keyword_lower))
        });
    }
    
    (stats, all_total_bytes, all_total_up, all_total_down)
}