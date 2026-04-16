"""
packet_builder.py
-----------------
Scapy 数据包构造与 TCP 端口扫描核心模块。

功能：
  - 构造任意 IP/TCP/ICMP 数据包
  - SYN 半开放扫描，判断端口开放 / 关闭状态
  - 封装 sr1 发送逻辑，统一超时与异常处理

依赖：scapy >= 2.5.0
运行要求：需要 root / Administrator 权限
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Optional

from scapy.layers.inet import IP, TCP, ICMP
from scapy.sendrecv import sr1, send

# ── 日志配置 ──────────────────────────────────────────────
logging.basicConfig(
    format="%(asctime)s [%(levelname)s] %(message)s",
    level=logging.INFO,
)
logger = logging.getLogger(__name__)


# ── TCP flag 常量 ─────────────────────────────────────────
class TCPFlags:
    FIN     = 0x01   # 请求断开连接
    SYN     = 0x02   # 发起连接请求
    RST     = 0x04   # 强制重置连接
    PSH     = 0x08   # 推送数据
    ACK     = 0x10   # 确认收到
    URG     = 0x20   # 紧急指针有效
    SYN_ACK = 0x12   # 同意连接（SYN + ACK）
    RST_ACK = 0x14   # 拒绝连接（RST + ACK）


# ── 扫描结果数据类 ─────────────────────────────────────────
@dataclass
class PortScanResult:
    target: str
    port: int
    state: str          # "open" | "closed" | "filtered"
    banner: str = ""


@dataclass
class ICMPProbeResult:
    target: str
    alive: bool
    src_ip: str = ""


# ── 数据包构造工具 ─────────────────────────────────────────
def build_icmp_packet(
    dst: str,
    ttl: int = 64,
    payload: bytes = b"scapy-probe",
) -> IP:
    """构造一个标准 ICMP Echo Request 数据包。"""
    from random import randint

    ip_id   = randint(1, 65535)
    icmp_id = randint(1, 65535)
    icmp_seq = randint(1, 65535)

    return (
        IP(dst=dst, ttl=ttl, id=ip_id)
        / ICMP(id=icmp_id, seq=icmp_seq)
        / payload
    )


def build_syn_packet(dst: str, dport: int, ttl: int = 64) -> IP:
    """构造一个 TCP SYN 数据包（用于半开放扫描）。"""
    return IP(dst=dst, ttl=ttl) / TCP(dport=dport, flags="S")


# ── 端口扫描 ───────────────────────────────────────────────
def scan_port(
    target: str,
    port: int,
    timeout: float = 1.0,
) -> PortScanResult:
    """
    对单个端口执行 SYN 扫描。

    返回值：
        PortScanResult，state 为 "open" / "closed" / "filtered"

    注意：
        SYN 扫描不完成三次握手，属于半开放扫描，需 root 权限。
    """
    packet = build_syn_packet(target, port)
    response = sr1(packet, timeout=timeout, verbose=False)

    if response is None:
        return PortScanResult(target=target, port=port, state="filtered")

    flags = response[TCP].flags if TCP in response else 0

    if flags == TCPFlags.SYN_ACK:
        state = "open"
    elif flags & TCPFlags.RST:
        state = "closed"
    else:
        state = "filtered"

    logger.info("  %s:%d -> %s", target, port, state)
    return PortScanResult(target=target, port=port, state=state)


def scan_ports(
    target: str,
    ports: list[int],
    timeout: float = 1.0,
) -> list[PortScanResult]:
    """批量扫描多个端口，返回所有结果列表。"""
    logger.info("开始扫描 %s，共 %d 个端口", target, len(ports))
    results = [scan_port(target, p, timeout) for p in ports]
    open_count = sum(1 for r in results if r.state == "open")
    logger.info("扫描完成，开放端口数：%d", open_count)
    return results


# ── 命令行入口 ─────────────────────────────────────────────
if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="TCP SYN 端口扫描器")
    parser.add_argument("target", help="目标 IP 或域名")
    parser.add_argument(
        "-p", "--ports",
        default="22,80,443,3306,8080",
        help="端口列表，逗号分隔（默认: 22,80,443,3306,8080）",
    )
    parser.add_argument("-t", "--timeout", type=float, default=1.0)
    args = parser.parse_args()

    port_list = [int(p) for p in args.ports.split(",")]
    results = scan_ports(args.target, port_list, args.timeout)

    print(f"\n{'端口':<8} {'状态':<10} {'目标'}")
    print("-" * 35)
    for r in results:
        print(f"{r.port:<8} {r.state:<10} {r.target}")