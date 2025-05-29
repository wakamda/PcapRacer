mod tshark;
mod stats;
mod location;
mod csv_output;

use std::env;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::time::Instant;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let url = "***REMOVED***";
    let token = "***REMOVED***y";

    let args: Vec<String> = env::args().collect();

    if args.len() == 2 && (args[1] == "-v" || args[1] == "--version") {
        println!("Version: {}", env!("CARGO_PKG_VERSION"));
        std::process::exit(0);
    }
    
    if args.len() == 2 && (args[1] == "-h" || args[1] == "--help") {
        print_usage();
        std::process::exit(0);
    }

    if args.len() == 3 && (args[1] == "-i") {

        if let Some(data) = location::query_single_ip(&args[2], url, token) {
            println!("IP: {}", data.ip);
            println!("位置信息: {}{}{}{}", data.country, data.province, data.city, data.isp);
        } else {
            println!("未能查询到该 IP 的归属信息");
        }
        std::process::exit(0);
    }

    if args.len() != 4 || args[1] != "-f" {
        eprintln!("❌ 参数错误！");
        print_usage();
        std::process::exit(1);
    }

    let input_pcap = &args[2];
    let output_csv = &args[3];
    let tshark_tsv = "test/temp_output.tsv";

    // 开始计时
    let start_time = Instant::now();

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
        url,
        token,
    );

    csv_output::write_csv(output_csv, &stats_map, &locations)?;

    println!("分析完成，结果已保存到 {}", output_csv);

    // 结束计时
    let duration = start_time.elapsed();
    println!("程序总耗时: {:.2?}", duration);
    Ok(())
}

fn print_usage() {
    println!("╔══════════════════════════════════════════════════════════╗");
    println!("║              🚀 PcapPracer 流量分析统计工具              ║");
    println!("╠══════════════════════════════════════════════════════════╣");
    println!("║ 用法:                                                    ║");
    // 设置宽度，左对齐
    println!("║   {:<55}║", format!("PcapRacer.exe -i <input_ip>"));
    println!("║   {:<55}║", format!("PcapRacer.exe -f <input_pcap> <output_csv>"));
    println!("║   {:<55}║", format!("PcapRacer.exe -h | --help"));
    println!("║                                                          ║");
    println!("║ 参数说明:                                                ║");
    println!("║   -i                                                     ║");
    println!("║         <input_ip>       对单个ip进行地理位置查询        ║");
    println!("║   -f                                                     ║");
    println!("║         <input_pcap>     要分析的 pcap 文件路径          ║");
    println!("║         <output_csv>     输出的 CSV 文件路径             ║");
    println!("║   -h, --help             显示帮助信息并退出              ║");
    println!("║   -v, --version          显示版本                        ║");
    println!("╚══════════════════════════════════════════════════════════╝");
}

