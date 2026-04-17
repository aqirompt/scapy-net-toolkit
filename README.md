# scapy-net-toolkit
scapy icmp scan

基于 [Scapy](https://scapy.net/) 的 Python 网络扫描与数据包构造工具集，
适用于授权渗透测试、网络教学与安全研究场景。

## 功能模块

| 模块                     | 功能                                 |
| ------------------------ | ------------------------------------ |
| `core/packet_builder.py` | TCP SYN 端口扫描、IP/ICMP 数据包构造 |
| `core/host_scanner.py`   | ICMP 主机存活探测、/24 网段批量扫描  |
| `utils/network_info.py`  | DNS 解析、WHOIS 信息搜集             |

## 快速开始

```bash
pip install -r requirements.txt

# 端口扫描（需 root）
sudo python core/packet_builder.py 192.168.1.1 -p 22,80,443

# 主机存活探测
sudo python core/host_scanner.py 192.168.1.0/24

# 单主机探测
sudo python core/host_scanner.py 192.168.1.1
```

