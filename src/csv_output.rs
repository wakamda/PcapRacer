use crate::stats::FlowStat;
use std::collections::HashMap;
use std::fs::File;
use std::io::{BufWriter, Write};
use csv::Writer;

pub fn write_csv(
    output_csv: &str,
    stats_map: &HashMap<String, FlowStat>,
    domains: &HashMap<String, String>,
    geoips: &HashMap<String, String>,
) -> Result<(), Box<dyn std::error::Error>> {
    // 创建文件 + 缓冲写入器
    let file = File::create(output_csv)?;
    let mut writer = BufWriter::new(file);

    // 写入 UTF-8 BOM：EF BB BF
    writer.write_all(b"\xEF\xBB\xBF")?;

    // 创建 CSV writer，基于已写入 BOM 的 writer
    let mut wtr = Writer::from_writer(writer);

    // 写表头
    wtr.write_record(&[
        "IP",
        "总数据包",
        "总数据量",
        "上行数据包",
        "上行数据量",
        "下行数据包",
        "下行数据量",
        "业务说明",
        "归属地",
    ])?;

    // 写内容
    let sorted_stats = sort_stats_by_total_pkts(stats_map);
    
    for (ip, stat) in sorted_stats.iter() {
        let domain = domains.get(ip).map(|s| s.as_str()).unwrap_or("");
        let geo = geoips.get(ip).map(|s| s.as_str()).unwrap_or("");

        wtr.write_record(&[
            ip,
            &stat.total_pkts.to_string(),
            &format_bytes(stat.total_bytes),
            &stat.up_pkts.to_string(),
            &format_bytes(stat.up_bytes),
            &stat.down_pkts.to_string(),
            &format_bytes(stat.down_bytes),
            domain,
            geo,
        ])?;
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
