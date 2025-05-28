mod tshark;
mod stats;
mod domain;
// mod geoip;
mod csv_output;

use std::collections::HashMap;
use std::env;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::fs;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();
    if args.len() != 3 {
        eprintln!("用法: {} <input_pcap> <output_csv>", args[0]);
        std::process::exit(1);
    }
    let input_pcap = &args[1];
    let output_csv = &args[2];
    let tshark_tsv = "temp_output.tsv";

    // 运行 tshark 生成 TSV
    tshark::run_tshark(input_pcap, tshark_tsv)?;

    // 读取TSV数据
    let file = File::open(tshark_tsv)?;
    let reader = BufReader::new(file);
    let lines: Vec<String> = reader.lines().filter_map(Result::ok).collect();

    // 识别局域网IP
    let local_ip = match stats::find_local_ip(&lines) {
        Ok(ip) => {
            println!("检测到局域网IP: {}", ip);
            ip
        }
        Err(e) => {
            eprintln!("错误: {}", e);
            std::process::exit(1);
        }
    };

    // 统计流量
    let stats_map = stats::aggregate_with_local_ip(&lines, &local_ip);

    // 解析域名和归属地
    let mut domains: HashMap<String, String> = HashMap::new();
    

    let mut geoips: HashMap<String, String> = HashMap::new();

    for ip in stats_map.keys() {
        // 解析域名

        // if let Some(db) = &geoip_db {
        //     geoips.insert(ip.clone(), db.get_city(ip).unwrap_or_default());
        // }
    }

    csv_output::write_csv(output_csv, &stats_map, &domains, &geoips)?;

    println!("分析完成，结果已保存到 {}", output_csv);

    // fs::remove_file(tshark_tsv)?;
    Ok(())
}
