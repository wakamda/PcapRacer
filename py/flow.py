from scapy.all import rdpcap, TCP, UDP, IP
from collections import defaultdict

# 读取 PCAP
packets = rdpcap("E:\0x00-PersonalProject\codeProgect\2025.5.28PcapRacer\test\20250807remotecontrol.pcapng")

# 存储流数据
flows = defaultdict(lambda: {
    "packets": 0,
    "bytes": 0,
    "up_bytes": 0,
    "down_bytes": 0
})

for pkt in packets:
    if IP in pkt:
        proto = None
        src_port = dst_port = 0
        if TCP in pkt:
            proto = "TCP"
            src_port = pkt[TCP].sport
            dst_port = pkt[TCP].dport
        elif UDP in pkt:
            proto = "UDP"
            src_port = pkt[UDP].sport
            dst_port = pkt[UDP].dport
        else:
            continue

        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst
        pkt_len = len(pkt)

        # 双向流 key（无论 A->B 还是 B->A 都算同一流）
        key = tuple(sorted([(src_ip, src_port), (dst_ip, dst_port)])) + (proto,)
        
        flows[key]["packets"] += 1
        flows[key]["bytes"] += pkt_len

        # 简单示例区分方向
        if (src_ip, src_port) == key[0]:
            flows[key]["up_bytes"] += pkt_len
        else:
            flows[key]["down_bytes"] += pkt_len

# 打印汇总
for k, v in flows.items():
    print(f"流 {k}: 包数={v['packets']}, 总字节={v['bytes']}, 上行={v['up_bytes']}, 下行={v['down_bytes']}")
