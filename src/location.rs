use serde::Deserialize;
use std::collections::HashMap;
use reqwest::blocking::Client;
use std::time::Duration;
use serde_json::json;

#[derive(Debug, Deserialize)]
struct RawIpInfo {
    #[serde(rename = "IP")]
    ip: String,

    #[serde(rename = "国家")]
    country: String,

    #[serde(rename = "省份")]
    province: String,

    #[serde(rename = "城市")]
    city: String,

    #[serde(rename = "运营商", default)]
    isp: String,
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
                    eprintln!("HTTP错误，状态码: {}", resp.status());
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
                                eprintln!("反序列化 IP 列表失败: {}", e);
                            }
                        }
                    }
                    Err(e) => {
                        eprintln!("读取响应体文本失败: {}", e);
                    }
                }
            }
            Err(e) => {
                eprintln!("请求失败: {}", e);
            }
        }       
        
        // 请求完毕后，sleep 2秒，防止被限速
        std::thread::sleep(std::time::Duration::from_secs(2));
    }

    results
}
