use serde::Deserialize;
use std::collections::HashMap;
use reqwest::blocking::Client;
use std::time::Duration;
use serde_json::json;
use std::net::{IpAddr, Ipv4Addr};

#[derive(Debug, Deserialize)]
pub struct RawIpInfo {
    #[serde(rename = "IP")]
    pub ip: String,

    #[serde(rename = "国家")]
    pub country: String,

    #[serde(rename = "省份")]
    pub province: String,

    #[serde(rename = "城市")]
    pub city: String,

    #[serde(rename = "运营商", default)]
    pub isp: String,
    // 还有其他字段你可以加上
}

pub fn query_ip_locations(
    ip_list: &[String],
    batch_size: usize,
    url: &str,
    token: &str,
) -> HashMap<String, String> {
    let client = Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .unwrap();

    let mut results = HashMap::new();

    for chunk in ip_list.chunks(batch_size) {
        let payload = json!({ "iplist": chunk });
        let full_url = format!("{}?token={}", url, token);

        match client.post(&full_url).json(&payload).send() {
            Ok(resp) => {
                if resp.status() != reqwest::StatusCode::OK {
                    eprintln!("❌ HTTP错误，状态码: {}", resp.status());
                    continue;
                }
        
                match resp.text() {
                    Ok(text) => {
                        // println!("接口返回原始 JSON:\n{}", text);
        
                        match serde_json::from_str::<Vec<RawIpInfo>>(&text) {
                            Ok(ip_infos) => {
                                for loc in ip_infos {
                                    let location_str = format!("{}{}{}{}", loc.country, loc.province, loc.city, loc.isp);
                                    results.insert(loc.ip, location_str);
                                }
                            }
                            Err(e) => {
                                eprintln!("❌ 反序列化 IP 列表失败: {}", e);
                            }
                        }
                    }
                    Err(e) => {
                        eprintln!("❌ 读取响应体文本失败: {}", e);
                    }
                }
            }
            Err(e) => {
                eprintln!("❌ 请求失败: {}", e);
            }
        }       
        
        // 请求完毕后，sleep 2秒，防止被限速
        std::thread::sleep(std::time::Duration::from_secs(1));
    }

    results
}


/// 查询单个 IP 的位置信息，先验证 IPv4 格式和公网性
pub fn query_single_ip(ip: &str, url: &str, token: &str) -> Option<RawIpInfo> {
    // 检查是否是合法的 IPv4
    let parsed_ip: Ipv4Addr = match ip.parse() {
        Ok(IpAddr::V4(addr)) => addr,
        _ => {
            eprintln!("❌ 无效的 IPv4 地址: {}", ip);
            return None;
        }
    };

    // 检查是否是公网 IP
    if !is_public_ipv4(&parsed_ip) {
        eprintln!("❌ 非公网 IPv4 地址: {}", ip);
        return None;
    }

    // 继续进行查询
    let client = Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .unwrap();

    let payload = json!({ "iplist": [ip] });
    let full_url = format!("{}?token={}", url, token);

    match client.post(&full_url).json(&payload).send() {
        Ok(resp) => {
            if resp.status() != reqwest::StatusCode::OK {
                eprintln!("❌ HTTP错误，状态码: {}", resp.status());
                return None;
            }

            match resp.text() {
                Ok(text) => {
                    match serde_json::from_str::<Vec<RawIpInfo>>(&text) {
                        Ok(mut ip_infos) => ip_infos.pop(),
                        Err(e) => {
                            eprintln!("❌ 反序列化单个 IP 失败: {}", e);
                            None
                        }
                    }
                }
                Err(e) => {
                    eprintln!("❌ 读取响应体文本失败: {}", e);
                    None
                }
            }
        }
        Err(e) => {
            eprintln!("❌ 请求失败: {}", e);
            None
        }
    }
}

fn is_public_ipv4(ip: &Ipv4Addr) -> bool {
    !(ip.is_private()
        || ip.is_loopback()
        || ip.is_link_local()
        || ip.is_broadcast()
        || ip.octets()[0] == 0   // 0.0.0.0/8
        || ip.octets()[0] >= 224) // 224.0.0.0/4 为多播和保留地址
}