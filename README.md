# 🚀 PcapRacer

`PcapRacer` 是一个用于分析 `.pcap` 网络抓包文件并生成流量统计的命令行工具。它支持单个 IP 的地理位置查询、单文件和批量文件分析，并输出 CSV 格式的统计结果。

---

## 🛠️ 前提

运行程序前请在项目根目录创建 `.env` 文件，并设置如下内容：

```env
API_URL=http://your-api-url.com/ipquery?token=xxxxxx
```

---

## 📦 功能特性

- 支持对单个 IP 进行归属地查询
- 支持对单个 pcap 文件进行流量统计
- 支持对整个文件夹中的多个 pcap 文件进行批量统计
- 输出结果为 `.csv`，便于查看与后续处理

---

## 📥 使用 Cargo 构建

```bash
cd PcapRacer
cargo build --release
```

---

## 使用

```bash
# 显示帮助信息
PcapRacer.exe -h
PcapRacer.exe --help

# 显示版本信息
PcapRacer.exe -v
PcapRacer.exe --version

# 查询 IP 地理位置
PcapRacer.exe -i <input_ip>

# 分析单个 pcap 文件，默认输出为同名 CSV 文件
PcapRacer.exe -f <input_pcap>

# 分析指定目录中的所有 pcap 文件
PcapRacer.exe -F <input_directory>

# 分析指定目录中的所有 pcap 文件并汇总，默认输出为同文件名 CSV 文件
PcapRacer.exe -F -A <input_directory>
```