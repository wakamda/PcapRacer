mod tshark;
mod stats;
mod location;
mod csv_output;

use std::env;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::time::Instant;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 开始计时
    let start_time = Instant::now();

    let args: Vec<String> = env::args().collect();
    if args.len() != 3 {
        eprintln!("用法: {} <input_pcap> <output_csv>", args[0]);
        std::process::exit(1);
    }
    let input_pcap = &args[1];
    let output_csv = &args[2];
    let tshark_tsv = "test/temp_output.tsv";

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

    // 统计流量并解析域名
    let stats_map = stats::aggregate_with_local_ip(&lines, &local_ip);

    // 解析IP归属地
    let ip_list: Vec<String> = stats_map.keys().cloned().collect();
    let locations = location::query_ip_locations(
        &ip_list,
        100,
        "***REMOVED***",
        "***REMOVED***y",
    );

    csv_output::write_csv(output_csv, &stats_map, &locations)?;

    println!("分析完成，结果已保存到 {}", output_csv);

    // 结束计时
    let duration = start_time.elapsed();
    println!("程序总耗时: {:.2?}", duration);
    Ok(())
}
