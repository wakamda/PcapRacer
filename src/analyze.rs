use crate::tshark;
use crate::stats;
use crate::location;
use crate::csv_output;

use std::{fs, path::{Path},io::{BufReader, BufRead}, fs::File};
use std::result::Result;
use indicatif::{ProgressBar, ProgressStyle};

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

pub fn run_analysis_one_ip(args: &String, api_url: &str) {
    if let Some(data) = location::query_single_ip(args, api_url) {
        println!("IP: {}", data.ip);
        println!("位置信息: {}{}{}{}", data.country, data.province, data.city, data.isp);
    } else {
        println!("未能查询到该 IP 的归属信息");
    }
    std::process::exit(0);
}