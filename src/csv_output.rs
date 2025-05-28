use crate::stats::FlowStat;
use std::collections::HashMap;
use std::fs::File;
use std::io::{BufWriter, Write};
use csv::Writer;

pub fn write_csv(
    output_csv: &str,
    stats_map: &HashMap<String, FlowStat>,
    geoips: &HashMap<String, String>,
) -> Result<(), Box<dyn std::error::Error>> {
    let file = File::create(output_csv)?;
    let mut writer = BufWriter::new(file);

    // 写入 UTF-8 BOM
    writer.write_all(b"\xEF\xBB\xBF")?;

    let mut wtr = Writer::from_writer(writer);

    let sorted_stats = sort_stats_by_total_pkts(stats_map);

    // 1️⃣ 计算最大域名数
    let max_domains = sorted_stats
        .iter()
        .map(|(_, stat)| stat.domains.len())
        .max()
        .unwrap_or(0);

    // 2️⃣ 写表头
    let mut header = vec![
        "IP",
        "总数据包",
        "总数据量",
        "上行数据包",
        "上行数据量",
        "下行数据包",
        "下行数据量",
    ];

    for i in 0..max_domains {
        header.push("业务说明");
    }
    header.push("归属地");

    wtr.write_record(&header)?;

    // 3️⃣ 写数据行
    for (ip, stat) in sorted_stats.iter() {
        let geo = geoips.get(ip).map(|s| s.as_str()).unwrap_or("");

        let mut record = vec![
            ip.clone(),
            stat.total_pkts.to_string(),
            format_bytes(stat.total_bytes),
            stat.up_pkts.to_string(),
            format_bytes(stat.up_bytes),
            stat.down_pkts.to_string(),
            format_bytes(stat.down_bytes),
        ];

        // 拿到所有域名并排序
        let mut domain_list: Vec<_> = stat.domains.iter().cloned().collect();
        domain_list.sort();

        for domain in &domain_list {
            record.push(domain.clone());
        }

        // 不足补空
        while record.len() < 7 + max_domains {
            record.push("".to_string());
        }

        record.push(geo.to_string());

        wtr.write_record(&record)?;
    }

    wtr.flush()?;
    Ok(())
}


pub fn format_bytes(bytes: u64) -> String {
    const KB: f64 = 1024.0;
    const MB: f64 = 1024.0 * 1024.0;

    let bytes_f64 = bytes as f64;

    if bytes_f64 >= MB {
        format!("{:.2} MB", bytes_f64 / MB)
    } else if bytes_f64 >= KB {
        format!("{:.2} KB", bytes_f64 / KB)
    } else {
        format!("{} B", bytes)
    }
}

pub fn sort_stats_by_total_pkts(
    stats: &HashMap<String, FlowStat>,
) -> Vec<(String, FlowStat)> {
    let mut vec: Vec<(String, FlowStat)> = stats
        .iter()
        .map(|(ip, stat)| (ip.clone(), stat.clone()))
        .collect();

    vec.sort_by(|a, b| b.1.total_pkts.cmp(&a.1.total_pkts)); // 降序

    vec
}
