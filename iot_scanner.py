#!/usr/bin/env python3
"""IoT Device Network Scanner (Windows-friendly, psutil + nmap discovery by default)

Features:
- Auto-detect local network CIDR using psutil
- Discover hosts using Nmap ping-scan (-sn) by default (works well on Windows)
- Optional ARP discovery using Scapy (use --arp) if you have Npcap and run as Admin
- Port scanning via Nmap (top ports, optional -sV for service detection)
- Simple risk scoring and CSV/JSON reports
"""

import argparse
import csv
import datetime
import ipaddress
import json
import os
import socket
import sys
from typing import Dict, List, Optional, Tuple

try:
    import psutil
except Exception as e:

    print("[!] Missing dependency 'psutil'. Install: pip install psutil")
    raise

try:
    import nmap  # python-nmap
except Exception as e:
    print("[!] Missing dependency 'python-nmap'. Install: pip install python-nmap")
    raise

SCAPY_AVAILABLE = True
try:
    import scapy.all as scapy  # type: ignore
    from scapy.error import Scapy_Exception
except Exception:
    SCAPY_AVAILABLE = False

try:
    from tabulate import tabulate
except Exception:
    print("[!] Missing dependency 'tabulate'. Install: pip install tabulate")
    raise


def detect_cidr(preferred_iface: Optional[str] = None) -> Optional[str]:
    addrs = psutil.net_if_addrs()
    if preferred_iface and preferred_iface in addrs:
        interfaces = {preferred_iface: addrs[preferred_iface]}
    else:
        interfaces = addrs

    for iface, addr_list in interfaces.items():
        for addr in addr_list:
            if getattr(addr, "family", None) == socket.AF_INET:
                ip = addr.address
                netmask = addr.netmask
                if not ip or not netmask:
                    continue
                if ip.startswith("169.254."):
                    continue
                try:
                    prefix = sum(bin(int(x)).count("1") for x in netmask.split("."))
                    network = ipaddress.IPv4Network(f"{ip}{prefix}", strict=False)
                    return str(network)
                except Exception:
                    continue
    return None


def nmap_discover(cidr: str) -> List[Dict[str, str]]:
    nm = nmap.PortScanner()
    try:
        nm.scan(hosts=cidr, arguments='-sn -T4')
    except Exception as e:
        print(f"[!] Nmap discovery error: {e}")
        return []

    hosts = []
    for h in nm.all_hosts():
        addresses = nm[h].get('addresses', {})
        ip = addresses.get('ipv4', addresses.get('ipv6', h))
        mac = addresses.get('mac', 'N/A')
        hosts.append({'ip': ip, 'mac': mac})
    return hosts


def scapy_arp_discover(cidr: str, iface: Optional[str] = None, timeout: int = 2) -> List[Dict[str, str]]:
    if not SCAPY_AVAILABLE:
        print("[!] Scapy not available in this environment. Install scapy and Npcap (Windows) to use ARP discovery.")
        return []

    try:
        if iface:
            answered, _ = scapy.arping(cidr, iface=iface, verbose=0, timeout=timeout)
        else:
            answered, _ = scapy.arping(cidr, verbose=0, timeout=timeout)
    except Exception as e:
        print(f"[!] Scapy ARP error: {e}")
        return []

    hosts = []
    for sent, recv in answered:
        hosts.append({'ip': recv.psrc, 'mac': recv.hwsrc})
    uniq = {h['ip']: h for h in hosts}
    return list(uniq.values())


def nmap_port_scan(ip: str, top_ports: int = 50, deep: bool = False) -> Dict[int, Dict]:
    nm = nmap.PortScanner()
    args = f"-T4 -Pn --top-ports {top_ports}"
    if deep:
        args += " -sV"
    results: Dict[int, Dict] = {}
    try:
        nm.scan(ip, arguments=args)
    except Exception as e:
        print(f"[!] Nmap scan error for {ip}: {e}")
        return results

    if ip not in nm.all_hosts():
        return results

    for proto in nm[ip].all_protocols():
        if proto not in ("tcp", "udp"):
            continue
        ports = nm[ip][proto].keys()
        for p in sorted(ports):
            info = nm[ip][proto][p]
            if info.get("state") == "open":
                results[int(p)] = {
                    "state": info.get("state", ""),
                    "name": info.get("name", ""),
                    "product": info.get("product", ""),
                    "version": info.get("version", ""),
"extrainfo": info.get("extrainfo", ""),
"proto": proto,
                }
    return results


HIGH_RISK_PORTS = {23, 21, 445, 3389, 1900, 5900}
MED_RISK_PORTS = {80, 8080, 5000, 5001, 1883, 5683, 139, 111, 8123, 554}
LOW_RISK_PORTS = {22, 53, 443, 5353, 8443}

RISK_REASONS = {
    23: "Telnet open (no encryption, often default creds).",
    21: "FTP open (plaintext credentials).",
    445: "SMB open (file sharing; high-risk if exposed).",
    3389: "RDP open (remote desktop; brute-force risk).",
    1900: "UPnP/SSDP open (device exposure).",
    5900: "VNC open (remote control; often weak auth).",
    80: "HTTP open (no TLS; check admin panels).",
    8080: "HTTP-alt open (often admin panels).",
    1883: "MQTT open (IoT messaging; check auth).",
    5683: "CoAP open (IoT UDP; check exposure).",
    554: "RTSP streaming (camera feed exposure).",
    22: "SSH open (secure if strong creds).",
    443: "HTTPS open (usually safer than HTTP).",
    5353: "mDNS (device discovery).",
    8443: "HTTPS-alt (admin panels).",
}


def assess_risk(open_ports: List[int]) -> Tuple[str, int, List[str]]:
    score = 0
    reasons: List[str] = []
    for p in open_ports:
        if p in HIGH_RISK_PORTS:
            score += 30
            reasons.append(RISK_REASONS.get(p, f"Port {p} high risk."))
        elif p in MED_RISK_PORTS:
            score += 15
            reasons.append(RISK_REASONS.get(p, f"Port {p} medium risk."))
        elif p in LOW_RISK_PORTS:
            score += 5
            if p in RISK_REASONS:
                reasons.append(RISK_REASONS[p])
        else:
            score += 8
    if (80 in open_ports or 8080 in open_ports) and (443 not in open_ports and 8443 not in open_ports):
        score += 5
        reasons.append("Web service without HTTPS detected.")
    if len(open_ports) >= 6:
        score += 10
        reasons.append("Many services exposed.")
    score = min(score, 100)
    if score >= 60:
        label = "HIGH"
    elif score >= 30:
        label = "MEDIUM"
    else:
        label = "LOW"
    return label, score, reasons


def save_reports(rows: List[Dict], prefix: str) -> Tuple[str, str]:
    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    csv_path = f"{prefix}_{ts}.csv"
    json_path = f"{prefix}_{ts}.json"
    headers = ["ip", "hostname", "mac", "open_ports", "risk_label", "risk_score", "risk_reasons"]

    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(headers)
        for r in rows:
            w.writerow([
                r.get("ip",""),
                r.get("hostname",""),
                r.get("mac",""),
                ",".join(str(p) for p in r.get("open_ports", [])),
                r.get("risk_label",""),
                r.get("risk_score",0),
                " | ".join(r.get("risk_reasons", [])),
            ])

    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(rows, f, indent=2)
    return csv_path, json_path


def main():
    parser = argparse.ArgumentParser(description="IoT Device Network Scanner")
    parser.add_argument("--cidr", help="Network CIDR (e.g., 192.168.1.0/24)")
    parser.add_argument("--arp", action="store_true", help="Use Scapy ARP discovery (requires Npcap + Admin)")
    parser.add_argument("--iface", help="Interface name to use for ARP (e.g., 'Wi-Fi')")
    parser.add_argument("--scan", action="store_true", help="Run port scans on discovered hosts (default: discovery only)")
    parser.add_argument("--deep", action="store_true", help="Deep scan (service/version detection)")
    parser.add_argument("--top-ports", type=int, default=50, help="Top N ports to scan")
    parser.add_argument("--output-prefix", default="scan_report", help="Filename prefix for CSV/JSON reports")
    args = parser.parse_args()

    cidr = args.cidr or detect_cidr(args.iface)
    if not cidr:
        print("[!] Could not auto-detect network. Provide --cidr manually (example: 192.168.1.0/24)")
        sys.exit(1)

    print(f"[*] Target network: {cidr}")
    hosts = []
    if args.arp:
        print("[*] Trying ARP discovery via Scapy... (requires Npcap + Admin)")
        hosts = scapy_arp_discover(cidr, iface=args.iface)
        if not hosts:
            print("[!] ARP discovery failed or returned no hosts. Falling back to Nmap discovery...")
            hosts = nmap_discover(cidr)
    else:
        print("[*] Using Nmap -sn discovery (recommended on Windows).")
    hosts = nmap_discover(cidr)

    if not hosts:
        print("[!] No hosts discovered. Check network, permissions, or CIDR.")
        sys.exit(1)

    print(f"[*] Found {len(hosts)} host(s).")
    rows = []
    for idx, h in enumerate(hosts, start=1):
        ip = h.get("ip")
        mac = h.get("mac", "")
        print(f"    ({idx}/{len(hosts)}) Host: {ip}  MAC: {mac}")
        services = {}
        open_ports = []
        if args.scan:
            services = nmap_port_scan(ip, top_ports=args.top_ports, deep=args.deep)
            open_ports = sorted(services.keys())
        hostname = ""
        try:
            hostname = socket.gethostbyaddr(ip)[0]
        except Exception:
            hostname = ""

        risk_label, risk_score, risk_reasons = assess_risk(open_ports)
        rows.append({
            "ip": ip,
            "hostname": hostname,
            "mac": mac,
            "open_ports": open_ports,
            "services": services,
            "risk_label": risk_label,
            "risk_score": risk_score,
            "risk_reasons": risk_reasons,
        })

    try:
        table = [[r["ip"], r["hostname"] or "-", r["mac"] or "-", ",".join(map(str, r["open_ports"])) or "-", r["risk_label"], r["risk_score"]] for r in rows]
        print("\n" + tabulate(table, headers=["IP","Hostname","MAC","Open Ports","Risk","Score"], tablefmt="github"))
    except Exception:
        for r in rows:
            print(f"- {r['ip']:15} {r['hostname'] or '-':30} {r['mac']:18} ports={r['open_ports']} risk={r['risk_label']}({r['risk_score']})")

    csv_path, json_path = save_reports(rows, args.output_prefix)
    print(f"\n[*] Saved: {csv_path}")
    print(f"[*] Saved: {json_path}")
    print("[*] Done. Use --scan to run port scans, or --arp to use Scapy ARP discovery (if you have Npcap).")


if __name__ == "__main__":
    main()
