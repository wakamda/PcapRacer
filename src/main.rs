mod tshark;
mod stats;
mod location;
mod csv_output;
mod analyze;

use std::env;
use std::time::Instant;
use std::process::Command;
use std::fs;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let url = "***REMOVED***";
    let token = "***REMOVED***y";

    let tshark_tsv = "temp_output.tsv";

    let args: Vec<String> = env::args().collect();
    let argc = args.len();

    match argc {
        0 => {
            eprintln!("❌ 参数错误！");
            print_usage();
            std::process::exit(1);
        }
        1 => {
            print_usage();
            std::process::exit(0);
        }
        2 => match args[1].as_str() {
            "-v" | "--version" => {
                println!("Version: {}", env!("CARGO_PKG_VERSION"));
                std::process::exit(0);
            }
            "-h" | "--help" => {
                print_usage();
                std::process::exit(0);
            }
            _ => {
                eprintln!("未知参数: {}", args[1]);
                print_usage();
                std::process::exit(1);
            }
        },
        3 => match args[1].as_str() {
            "-i" => {
                analyze::run_analysis_one_ip(&args[2], url, token);
            }
            "-f" => {
                if !check_tshark() {
                    std::process::exit(1);
                }
                let start_time = Instant::now();
                let input_pcap = &args[2];

                analyze::analyze_single_file(input_pcap, url, token,tshark_tsv)?;

                let duration = start_time.elapsed();
                println!("程序总耗时: {:.2?}", duration);
            }
            "-F" => {
                if !check_tshark() {
                    std::process::exit(1);
                }
                let start_time = Instant::now();
                let dir_path = &args[2];

                analyze::analyze_directory(dir_path, url, token,tshark_tsv)?;

                let duration = start_time.elapsed();
                println!("程序总耗时: {:.2?}", duration);
            }
            _ => {
                eprintln!("❌ 参数错误！");
                print_usage();
                std::process::exit(1);
            }
        },
        4.. => {
            eprintln!("❌ 参数错误！");
            print_usage();
            std::process::exit(1);
        }
    }

    fs::remove_file("temp_output.tsv")?;
    Ok(())
}

fn print_usage() {
    println!("╔══════════════════════════════════════════════════════════╗");
    println!("║              🚀 PcapPracer 流量分析统计工具              ║");
    println!("╠══════════════════════════════════════════════════════════╣");
    println!("║ 用法:                                                    ║");
    // 设置宽度，左对齐
    println!("║   {:<55}║", format!("PcapRacer.exe -h | --help"));
    println!("║   {:<55}║", format!("PcapRacer.exe -v | --version"));
    println!("║   {:<55}║", format!("PcapRacer.exe -i <input_ip>"));
    println!("║   {:<55}║", format!("PcapRacer.exe -f <input_pcap> [output_csv]"));
    println!("║                                                          ║");
    println!("║    输出的 CSV 文件名默认为 原文件名.csv                  ║");
    println!("║                                                          ║");
    println!("║ 参数说明:                                                ║");
    println!("║   -i                                                     ║");
    println!("║         <input_ip>       对单个ip进行地理位置查询        ║");
    println!("║   -f                                                     ║");
    println!("║         <input_pcap>     要分析的 pcap 文件路径 (必需)   ║");
    println!("║   -F                                                     ║");
    println!("║         <input_Dir>     要分析的 pcap 文件夹路径 (必需)  ║");
    println!("║                      注意:此项将分析文件夹内所有pcap文件 ║");
    println!("║                                                          ║");
    println!("║   -h, --help             显示帮助信息并退出              ║");
    println!("║                                                          ║");
    println!("║   -v, --version          显示版本                        ║");
    println!("╚══════════════════════════════════════════════════════════╝");
}

fn check_tshark() -> bool {
    match Command::new("tshark").arg("--version").output() {
        Ok(output) => {
            if output.status.success() {
                let version = String::from_utf8_lossy(&output.stdout);
                println!("检测到 tshark 版本：{}", version.lines().next().unwrap_or("未知"));
                true
            } else {
                eprintln!("❌ tshark 检查失败，请确保已安装 tshark(wireshark) 并在 PATH 中可用。");
                false
            }
        }
        Err(_) => {
            eprintln!("❌ 无法执行 tshark，请确保已安装 tshark(wireshark) 并在 PATH 中可用。");
            false
        }
    }
}