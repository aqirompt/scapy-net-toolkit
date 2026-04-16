"""
host_scanner.py
---------------
基于 ICMP 的主机存活探测模块（信息搜集阶段）。

功能：
  - 探测单个主机是否在线
  - 批量扫描整个 /24 网段
  - 随机化 IP ID / ICMP ID / 序列号，降低特征指纹

依赖：scapy >= 2.5.0
运行要求：需要 root / Administrator 权限
"""

from __future__ import annotations

import ipaddress
import logging
from random import randint
from typing import Generator

from scapy.layers.inet import IP, ICMP
from scapy.sendrecv import sr1

logger = logging.getLogger(__name__)


def probe_host(
    target: str,
    ttl: int = 64,
    timeout: float = 1.0,
    payload: bytes = b"probe",
) -> tuple[bool, str]:
    """
    向目标发送一个 ICMP Echo Request，判断主机是否存活。

    参数：
        target  : 目标 IP 地址
        ttl     : IP TTL（Linux=64, Windows=128, 路由器=255）
        timeout : 等待响应的超时秒数
        payload : 自定义载荷（可用于特征标记）

    返回：
        (is_alive: bool, src_ip: str)
    """
    packet = (
        IP(dst=target, ttl=ttl, id=randint(1, 65535))
        / ICMP(id=randint(1, 65535), seq=randint(1, 65535))
        / payload
    )

    response = sr1(packet, timeout=timeout, verbose=False)

    if response and ICMP in response:
        src = response[IP].src
        logger.info("[+] %s is alive (src: %s)", target, src)
        return True, src

    logger.debug("[-] %s: no response", target)
    return False, ""


def sweep_subnet(
    subnet: str,
    ttl: int = 64,
    timeout: float = 0.5,
) -> Generator[tuple[str, bool, str], None, None]:
    """
    扫描一个 CIDR 网段内的所有主机。

    参数：
        subnet  : CIDR 格式，如 "192.168.1.0/24"
        ttl     : ICMP TTL 值
        timeout : 每个主机的超时秒数

    生成：
        (ip, is_alive, src_ip) 三元组

    示例：
        for ip, alive, _ in sweep_subnet("192.168.1.0/24"):
            if alive:
                print(ip)
    """
    network = ipaddress.ip_network(subnet, strict=False)
    hosts = list(network.hosts())
    logger.info("开始扫描网段 %s，共 %d 个主机", subnet, len(hosts))

    for host in hosts:
        ip_str = str(host)
        alive, src = probe_host(ip_str, ttl=ttl, timeout=timeout)
        yield ip_str, alive, src


# ── 命令行入口 ─────────────────────────────────────────────
if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="ICMP 主机存活探测")
    parser.add_argument("target", help="单个 IP 或 CIDR 网段（如 192.168.1.0/24）")
    parser.add_argument("-t", "--timeout", type=float, default=1.0)
    parser.add_argument("--ttl", type=int, default=64)
    parser.add_argument(
        "--payload",
        default="probe",
        help="ICMP 载荷内容（ASCII，默认: probe）",
    )
    args = parser.parse_args()

    try:
        # 判断是网段还是单个 IP
        network = ipaddress.ip_network(args.target, strict=False)
        if network.num_addresses > 1:
            alive_hosts = []
            for ip, alive, _ in sweep_subnet(
                args.target, ttl=args.ttl, timeout=args.timeout
            ):
                if alive:
                    alive_hosts.append(ip)
            print(f"\n存活主机（共 {len(alive_hosts)} 个）：")
            for h in alive_hosts:
                print(f"  {h}")
        else:
            raise ValueError
    except ValueError:
        alive, src = probe_host(
            args.target,
            ttl=args.ttl,
            timeout=args.timeout,
            payload=args.payload.encode(),
        )
        status = f"alive (reply from {src})" if alive else "down / no response"
        print(f"{args.target}: {status}")