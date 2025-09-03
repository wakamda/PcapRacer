import csv
from collections import defaultdict
import sys
import os

# 检查命令行参数
if len(sys.argv) < 2:
    print("用法: python script.py <input_csv_path>")
    sys.exit(1)

input_path = sys.argv[1]

if not os.path.exists(input_path):
    print(f"文件不存在: {input_path}")
    sys.exit(1)

# 输出文件名，可根据输入文件名生成
output_path = os.path.splitext(input_path)[0] + "_by_domain.csv"

# 用于汇总域名数据
domain_agg = defaultdict(lambda: {
    "总数据包": 0,
    "总字节数": 0,
    "总数据量": 0.0,  # MB
    "上行数据包": 0,
    "上行字节数": 0,
    "上行数据量": 0.0,
    "下行数据包": 0,
    "下行字节数": 0,
    "下行数据量": 0.0,
    "归属地": set()
})

# 读取 CSV 并汇总
with open(input_path, "r", encoding="utf-8") as f:
    reader = csv.DictReader(f)
    for row in reader:
        # 使用第一个业务说明字段作为域名 key
        domain = row["业务说明"]
        if not domain:
            continue
        agg = domain_agg[domain]
        agg["总数据包"] += int(row["总数据包"])
        agg["总字节数"] += int(row["总字节数"])
        agg["总数据量"] += float(row["总数据量"].replace(" MB","").replace(" KB","")) if "MB" in row["总数据量"] else float(row["总数据量"].replace(" KB",""))/1024
        agg["上行数据包"] += int(row["上行数据包"])
        agg["上行字节数"] += int(row["上行字节数"])
        agg["上行数据量"] += float(row["上行数据量"].replace(" MB","").replace(" KB","")) if "MB" in row["上行数据量"] else float(row["上行数据量"].replace(" KB",""))/1024
        agg["下行数据包"] += int(row["下行数据包"])
        agg["下行字节数"] += int(row["下行字节数"])
        agg["下行数据量"] += float(row["下行数据量"].replace(" MB","").replace(" KB","")) if "MB" in row["下行数据量"] else float(row["下行数据量"].replace(" KB",""))/1024
        agg["归属地"].add(row["归属地"])

# 按总字节数降序排列
sorted_domains = sorted(domain_agg.items(), key=lambda x: x[1]["总字节数"], reverse=True)

# 写入新的 CSV
with open(output_path, "w", newline="", encoding="utf-8") as f:
    fieldnames = ["域名","总数据包","总字节数","总数据量(MB)","上行数据包","上行字节数","上行数据量(MB)",
                  "下行数据包","下行字节数","下行数据量(MB)","归属地"]
    writer = csv.DictWriter(f, fieldnames=fieldnames)
    writer.writeheader()
    for domain, data in sorted_domains:
        writer.writerow({
            "域名": domain,
            "总数据包": data["总数据包"],
            "总字节数": data["总字节数"],
            "总数据量(MB)": round(data["总数据量"], 2),
            "上行数据包": data["上行数据包"],
            "上行字节数": data["上行字节数"],
            "上行数据量(MB)": round(data["上行数据量"], 2),
            "下行数据包": data["下行数据包"],
            "下行字节数": data["下行字节数"],
            "下行数据量(MB)": round(data["下行数据量"], 2),
            "归属地": ";".join(data["归属地"])
        })

print(f"处理完成，输出文件: {output_path}")
