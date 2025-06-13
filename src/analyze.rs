use crate::tshark;
use crate::stats;
use crate::location;
use crate::csv_output;

use std::{fs, path::{Path},io::{BufReader, BufRead}, fs::File};
use std::result::Result;
use indicatif::{ProgressBar, ProgressStyle};
use std::collections::HashMap;
use crate::stats::FlowStat;
use std::path::PathBuf;

pub fn parse_and_aggregate(
    input_pcap: &str,
    tshark_tsv: &str,
) -> Result<(HashMap<String, FlowStat>, u64, u64, u64, String), Box<dyn std::error::Error>> {
    tshark::run_tshark(input_pcap, tshark_tsv)?;

    let file = File::open(tshark_tsv)?;
    let reader = BufReader::new(file);
    let lines: Vec<String> = reader.lines().filter_map(Result::ok).collect();

    let local_ip = match stats::find_local_ip(&lines) {
        Ok(ip) => {
            println!("⏳ 定位到局域网IP: {}", ip);
            ip
        }
        Err(e) => {
            eprintln!("❌ 错误: {}", e);
            std::process::exit(1);
        }
    };

    let (stats_map, total, up, down) = stats::aggregate_with_local_ip(&lines, &local_ip);
    Ok((stats_map, total, up, down, local_ip))
}


// 分析单个文件
pub fn analyze_single_file(input_pcap: &str, api_url: &str, tshark_tsv:&str) -> Result<(), Box<dyn std::error::Error>> {
    // 输出文件名
    let output_csv = {
        let path = Path::new(input_pcap);
        let stem = path.file_stem().unwrap_or_default();
        let parent = path.parent().unwrap_or_else(|| Path::new("."));
        let mut output_path = parent.join(stem);
        output_path.set_extension("csv");
        output_path.to_string_lossy().to_string()
    };


    tshark::run_tshark(input_pcap, tshark_tsv)?;


    let file = File::open(tshark_tsv)?;
    let reader = BufReader::new(file);
    let lines: Vec<String> = reader.lines().filter_map(Result::ok).collect();

    let local_ip = match stats::find_local_ip(&lines) {
        Ok(ip) => {
            println!("⏳ 定位到局域网IP: {}", ip);
            ip
        }
        Err(e) => {
            eprintln!("❌ 错误: {}", e);
            std::process::exit(1);
        }
    };

    let (stats_map, total, up, down) = stats::aggregate_with_local_ip(&lines, &local_ip);

    if !api_url.is_empty() {
        let ip_list: Vec<String> = stats_map.keys().cloned().collect();
        let locations = location::query_ip_locations(&ip_list, 100, api_url);

        csv_output::write_csv(&output_csv, &stats_map, &locations, total, up, down)?;

        println!("✅ 分析完成，结果已保存到 {}", output_csv);
    }
    
    Ok(())
}

// 分析目录中所有 pcap 和 pcapng 文件
pub fn analyze_directory(dir_path: &str, api_url: &str, tshark_tsv:&str) -> Result<(), Box<dyn std::error::Error>> {
    let path = Path::new(dir_path);
    if !path.is_dir() {
        eprintln!("❌ {} 不是一个目录", dir_path);
        std::process::exit(1);
    }

    // 收集所有符合条件的文件
    let files: Vec<_> = fs::read_dir(path)?
        .filter_map(|entry| {
            let entry = entry.ok()?;
            let file_path = entry.path();
            if file_path.is_file() {
                if let Some(ext) = file_path.extension() {
                    if ext == "pcap" || ext == "pcapng" {
                        return Some(file_path);
                    }
                }
            }
            None
        })
        .collect();

    if files.is_empty() {
        eprintln!("⚠️ 目录 {} 中没有找到 .pcap 或 .pcapng 文件", dir_path);
        std::process::exit(0);
    }

    let pb = ProgressBar::new(files.len() as u64);
    pb.set_style(
        ProgressStyle::default_bar()
            .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} {msg}")
            .unwrap()
            .progress_chars("#>-"),
    );

    for file_path in files {
        pb.set_message(format!("分析文件: {}", file_path.display()));
        analyze_single_file(file_path.to_str().unwrap(), api_url, tshark_tsv)?;
        pb.inc(1);
    }

    pb.finish_with_message("全部文件分析完成");
    Ok(())
}

pub fn analyze_directory_merged(
    dir_path: &str,
    api_url: &str,
    tshark_tsv: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let path = Path::new(dir_path);
    if !path.is_dir() {
        eprintln!("❌ {} 不是一个目录", dir_path);
        std::process::exit(1);
    }

    // 输出文件名
    let output_csv = get_output_csv_path(dir_path);

    let files: Vec<_> = fs::read_dir(path)?
        .filter_map(|entry| {
            let entry = entry.ok()?;
            let file_path = entry.path();
            if file_path.is_file() {
                if let Some(ext) = file_path.extension() {
                    if ext == "pcap" || ext == "pcapng" {
                        return Some(file_path);
                    }
                }
            }
            None
        })
        .collect();

    if files.is_empty() {
        eprintln!("⚠️ 目录 {} 中没有找到 .pcap 或 .pcapng 文件", dir_path);
        std::process::exit(0);
    }

    let pb = ProgressBar::new(files.len() as u64);
    pb.set_style(
        ProgressStyle::default_bar()
            .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} {msg}")
            .unwrap()
            .progress_chars("#>-"),
    );

    let mut global_stats_map: HashMap<String, FlowStat> = HashMap::new();
    let mut total_all = 0;
    let mut up_all = 0;
    let mut down_all = 0;

    for file_path in files {
        pb.set_message(format!("分析文件: {}", file_path.display()));
        let (stats_map, total, up, down, _local_ip) =
            parse_and_aggregate(file_path.to_str().unwrap(), tshark_tsv)?;

        // 合并当前 stats_map 到 global_stats_map
        for (ip, stat) in stats_map {
            global_stats_map
                .entry(ip)
                .and_modify(|s| {
                    s.total_pkts += stat.total_pkts;
                    s.total_bytes += stat.total_bytes;
                    s.up_pkts += stat.up_pkts;
                    s.up_bytes += stat.up_bytes;
                    s.down_pkts += stat.down_pkts;
                    s.down_bytes += stat.down_bytes;
                })
                .or_insert(stat);
        }

        total_all += total;
        up_all += up;
        down_all += down;
        pb.inc(1);
    }

    // 查询归属地
    if !api_url.is_empty() {
        let ip_list: Vec<String> = global_stats_map.keys().cloned().collect();
        let locations = location::query_ip_locations(&ip_list, 100, api_url);

        csv_output::write_csv(&output_csv, &global_stats_map, &locations, total_all, up_all, down_all).unwrap();
        println!("✅ 所有文件分析完成，结果已保存到 {}", &output_csv);
    }

    pb.finish_with_message("全部文件分析完成");
    Ok(())
}


pub fn run_analysis_one_ip(args: &String, api_url: &str) {
    if let Some(data) = location::query_single_ip(args, api_url) {
        println!("IP: {}", data.ip);
        println!("位置信息: {}{}{}{}", data.country, data.province, data.city, data.isp);
    } else {
        println!("未能查询到该 IP 的归属信息");
    }
    std::process::exit(0);
}

//获取绝对文件夹路径
fn get_output_csv_path(dir_path: &str) -> String {
    // 将输入路径转为绝对路径
    let abs_path = fs::canonicalize(dir_path).unwrap_or_else(|_| PathBuf::from(dir_path));

    // 获取目录名（即最后一级目录）
    let dir_name = abs_path.file_name()
        .or_else(|| abs_path.components().last().map(|c| c.as_os_str()))
        .unwrap_or_else(|| std::ffi::OsStr::new("output"));

    // 构造输出路径（在当前目录下生成 dir_name.csv）
    let mut output_path = abs_path.join(dir_name);
    output_path.set_extension("csv");

    output_path.to_string_lossy().to_string()
}