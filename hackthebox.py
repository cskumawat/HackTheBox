#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import datetime as dt
import json
import os
import platform
import re
import shutil
import socket
import subprocess
import sys
import time
from typing import Any, Dict, List, Optional, Tuple

import psutil

try:
    import requests
except Exception:
    requests = None

try:
    import miniupnpc  # type: ignore
except Exception:
    miniupnpc = None


# ----------------------- helpers -----------------------

def now_utc() -> str:
    return dt.datetime.utcnow().replace(microsecond=0).isoformat() + "Z"


def is_windows() -> bool:
    return platform.system().lower().startswith("win")


def is_macos() -> bool:
    return platform.system().lower() == "darwin"


def is_linux() -> bool:
    return platform.system().lower() == "linux"


def which(cmd: str) -> Optional[str]:
    return shutil.which(cmd)


def run_cmd(cmd: List[str], timeout: int = 10, limit: int = 200_000) -> Dict[str, Any]:
    out = {"cmd": cmd, "ok": False, "returncode": None, "stdout": "", "stderr": ""}
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False)
        stdout = (p.stdout or "")[:limit].strip()
        stderr = (p.stderr or "")[:limit].strip()
        out.update(ok=True, returncode=p.returncode, stdout=stdout, stderr=stderr)
        return out
    except subprocess.TimeoutExpired:
        out.update(ok=False, stderr="TIMEOUT")
        return out
    except Exception as e:
        out.update(ok=False, stderr=f"ERROR: {e}")
        return out


def safe_int(x: Any) -> Optional[int]:
    try:
        return int(x)
    except Exception:
        return None


def guess_iface_type(name: str) -> str:
    n = name.lower()
    if "wifi" in n or "wlan" in n or "wi-fi" in n:
        return "wifi"
    if "eth" in n or "en" in n:
        return "ethernet"
    if "tun" in n or "tap" in n or "vpn" in n or "wg" in n:
        return "vpn"
    if "loopback" in n or n in ("lo",):
        return "loopback"
    return "unknown"


# ----------------------- CSV parsing (router exports) -----------------------

def read_csv_file(path: str) -> List[Dict[str, str]]:
    rows: List[Dict[str, str]] = []
    with open(path, "r", encoding="utf-8", newline="") as f:
        reader = csv.DictReader(f)
        for r in reader:
            rows.append({k.strip(): (v.strip() if isinstance(v, str) else "") for k, v in r.items() if k})
    return rows


def normalize_mac(mac: str) -> str:
    m = mac.strip().lower().replace("-", ":")
    if re.fullmatch(r"([0-9a-f]{2}:){5}[0-9a-f]{2}", m):
        return m
    return mac.strip()


def parse_dhcp_leases(path: Optional[str]) -> Dict[str, Any]:
    if not path:
        return {"present": False, "lease_count": 0, "leases": [], "error": None}
    if not os.path.exists(path):
        return {"present": False, "lease_count": 0, "leases": [], "error": f"file not found: {path}"}

    rows = read_csv_file(path)

    # common header names: IP, MAC, Hostname, Expires, Lease Time, Interface
    leases = []
    for r in rows:
        ip = r.get("IP") or r.get("ip") or r.get("Address") or r.get("IPv4") or ""
        mac = r.get("MAC") or r.get("mac") or r.get("MAC Address") or ""
        host = r.get("Hostname") or r.get("Host") or r.get("Name") or ""
        exp = r.get("Expires") or r.get("Expiry") or r.get("Lease Expiration") or ""
        leases.append({
            "ip": ip,
            "mac": normalize_mac(mac),
            "hostname": host,
            "expires": exp,
            "raw": r,
        })

    return {"present": True, "lease_count": len(leases), "leases": leases, "error": None}


def parse_clients(path: Optional[str], kind: str) -> Dict[str, Any]:
    if not path:
        return {"present": False, "count": 0, "clients": [], "error": None, "kind": kind}
    if not os.path.exists(path):
        return {"present": False, "count": 0, "clients": [], "error": f"file not found: {path}", "kind": kind}

    rows = read_csv_file(path)
    clients = []
    for r in rows:
        ip = r.get("IP") or r.get("ip") or r.get("Address") or ""
        mac = r.get("MAC") or r.get("mac") or r.get("MAC Address") or ""
        name = r.get("Name") or r.get("Hostname") or r.get("Client") or ""
        iface = r.get("Interface") or r.get("Port") or r.get("Band") or ""
        clients.append({"ip": ip, "mac": normalize_mac(mac), "name": name, "iface": iface, "raw": r})

    return {"present": True, "count": len(clients), "clients": clients, "error": None, "kind": kind}


def parse_port_forwards(path: Optional[str]) -> Dict[str, Any]:
    if not path:
        return {"present": False, "count": 0, "rules": [], "error": None}
    if not os.path.exists(path):
        return {"present": False, "count": 0, "rules": [], "error": f"file not found: {path}"}

    rows = read_csv_file(path)
    rules = []
    for r in rows:
        rules.append({
            "name": r.get("Name") or r.get("Service") or r.get("Rule") or "",
            "proto": (r.get("Protocol") or r.get("proto") or "").lower(),
            "wan_port": r.get("External Port") or r.get("WAN Port") or r.get("Public Port") or r.get("Port") or "",
            "lan_ip": r.get("Internal IP") or r.get("LAN IP") or r.get("Server IP") or "",
            "lan_port": r.get("Internal Port") or r.get("LAN Port") or r.get("Private Port") or "",
            "enabled": r.get("Enabled") or r.get("On") or "",
            "raw": r,
        })
    return {"present": True, "count": len(rules), "rules": rules, "error": None}


# ----------------------- local collectors -----------------------

def collect_system() -> Dict[str, Any]:
    boot = psutil.boot_time()
    hostname = socket.gethostname()
    fqdn = socket.getfqdn()

    users = []
    try:
        for u in psutil.users():
            users.append({
                "name": u.name,
                "terminal": u.terminal,
                "host": u.host,
                "started": dt.datetime.fromtimestamp(u.started).isoformat(),
            })
    except Exception:
        pass

    tz_guess = time.tzname[0] if time.tzname else None

    return {
        "time_utc": now_utc(),
        "os_system": platform.system(),
        "os_release": platform.release(),
        "os_version": platform.version(),
        "platform_string": platform.platform(),
        "machine_arch": platform.machine(),
        "processor": platform.processor(),
        "python_version": sys.version,
        "hostname": hostname,
        "fqdn": fqdn,
        "boot_time_utc": dt.datetime.utcfromtimestamp(boot).replace(microsecond=0).isoformat() + "Z",
        "uptime_seconds": max(0, int(time.time() - boot)),
        "current_user": os.environ.get("USERNAME") or os.environ.get("USER") or None,
        "logged_in_users": users,
        "logged_in_user_count": len(users),
        "timezone_guess": tz_guess,
    }


def collect_interfaces() -> Dict[str, Any]:
    addrs = psutil.net_if_addrs()
    stats = psutil.net_if_stats()
    io = psutil.net_io_counters(pernic=True)

    data: Dict[str, Any] = {"iface_count": 0, "iface_names": [], "ifaces": {}}

    for name, addr_list in addrs.items():
        st = stats.get(name)
        nic = {
            "name": name,
            "type_guess": guess_iface_type(name),
            "is_up": st.isup if st else None,
            "speed_mbps": st.speed if st else None,
            "mtu": st.mtu if st else None,
            "duplex": str(st.duplex) if st else None,
            "mac": None,
            "ipv4": [],
            "ipv6": [],
            "addresses_raw": [],
            "io": None,
        }

        for a in addr_list:
            fam = a.family
            fam_name = str(fam)
            if fam == socket.AF_INET:
                fam_name = "IPv4"
            elif fam == socket.AF_INET6:
                fam_name = "IPv6"
            elif hasattr(psutil, "AF_LINK") and fam == psutil.AF_LINK:
                fam_name = "MAC"

            rec = {
                "family": fam_name,
                "address": a.address,
                "netmask": getattr(a, "netmask", None),
                "broadcast": getattr(a, "broadcast", None),
                "ptp": getattr(a, "ptp", None),
            }
            nic["addresses_raw"].append(rec)

            if fam_name == "MAC" and a.address:
                nic["mac"] = a.address
            elif fam_name == "IPv4":
                nic["ipv4"].append(rec)
            elif fam_name == "IPv6":
                # include a quick scope hint
                scope = "global"
                if "%" in a.address or a.address.lower().startswith("fe80:"):
                    scope = "link_local"
                rec["scope"] = scope
                nic["ipv6"].append(rec)

        nic_io = io.get(name)
        if nic_io:
            nic["io"] = {
                "rx_bytes": nic_io.bytes_recv,
                "tx_bytes": nic_io.bytes_sent,
                "rx_packets": nic_io.packets_recv,
                "tx_packets": nic_io.packets_sent,
                "rx_errors": nic_io.errin,
                "tx_errors": nic_io.errout,
                "rx_drops": nic_io.dropin,
                "tx_drops": nic_io.dropout,
            }

        data["ifaces"][name] = nic

    data["iface_names"] = sorted(list(data["ifaces"].keys()))
    data["iface_count"] = len(data["iface_names"])
    return data


def collect_routing() -> Dict[str, Any]:
    out: Dict[str, Any] = {
        "default_gateway_ip": None,
        "default_gateway_iface": None,
        "routes_raw": None,
        "route_table_count_estimate": None,
        "has_ipv6_default_route": None,
        "tool_output": {},
    }

    if is_linux():
        r = run_cmd(["sh", "-lc", "ip route show"])
        out["tool_output"]["ip_route"] = r
        raw = r.get("stdout", "")
        out["routes_raw"] = raw
        out["route_table_count_estimate"] = len([x for x in raw.splitlines() if x.strip()])
        gw = None
        gw_if = None
        for line in raw.splitlines():
            if line.startswith("default "):
                m = re.search(r"\bvia\s+([0-9.]+)", line)
                if m:
                    gw = m.group(1)
                m2 = re.search(r"\bdev\s+(\S+)", line)
                if m2:
                    gw_if = m2.group(1)
        out["default_gateway_ip"] = gw
        out["default_gateway_iface"] = gw_if
        out["has_ipv6_default_route"] = bool(run_cmd(["sh", "-lc", "ip -6 route show default"]).get("stdout"))

    elif is_macos():
        r = run_cmd(["sh", "-lc", "netstat -rn"])
        out["tool_output"]["netstat_rn"] = r
        out["routes_raw"] = r.get("stdout", "")
        out["route_table_count_estimate"] = len([x for x in (r.get("stdout") or "").splitlines() if x.strip()])
        g = run_cmd(["sh", "-lc", "route -n get default | head -n 80"])
        out["tool_output"]["route_get_default"] = g
        gw = None
        iface = None
        for line in (g.get("stdout") or "").splitlines():
            if line.strip().startswith("gateway:"):
                gw = line.split("gateway:", 1)[1].strip()
            if line.strip().startswith("interface:"):
                iface = line.split("interface:", 1)[1].strip()
        out["default_gateway_ip"] = gw
        out["default_gateway_iface"] = iface

    elif is_windows():
        r = run_cmd(["cmd", "/c", "route print"])
        out["tool_output"]["route_print"] = r
        raw = (r.get("stdout") or "")
        out["routes_raw"] = raw[:4000]
        out["route_table_count_estimate"] = len([x for x in raw.splitlines() if x.strip()])
        gw = None
        for line in raw.splitlines():
            line = line.strip()
            if line.startswith("0.0.0.0") and "0.0.0.0" in line:
                parts = line.split()
                if len(parts) >= 3 and re.match(r"^\d+\.\d+\.\d+\.\d+$", parts[2]):
                    gw = parts[2]
                    break
        out["default_gateway_ip"] = gw

    return out


def collect_neighbors() -> Dict[str, Any]:
    if is_linux():
        n = run_cmd(["sh", "-lc", "ip neigh show"])
        raw = n.get("stdout", "")
    elif is_macos():
        n = run_cmd(["sh", "-lc", "arp -a"])
        raw = n.get("stdout", "")
    elif is_windows():
        n = run_cmd(["cmd", "/c", "arp -a"])
        raw = n.get("stdout", "")
    else:
        n = {"ok": False}
        raw = ""

    # parse some common patterns
    neighbors = []
    for line in raw.splitlines():
        line = line.strip()
        # Windows:  192.168.1.1          aa-bb-cc-dd-ee-ff     dynamic
        m_win = re.match(r"^(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F-]{17})\s+(\S+)", line)
        if m_win:
            neighbors.append({"ip": m_win.group(1), "mac": normalize_mac(m_win.group(2)), "state": m_win.group(3), "raw": line})
            continue
        # Linux ip neigh: 192.168.1.1 dev wlan0 lladdr aa:bb:... REACHABLE
        m_lin = re.match(r"^(\d+\.\d+\.\d+\.\d+)\s+dev\s+(\S+)\s+lladdr\s+([0-9a-f:]{17})\s+(\S+)", line, re.I)
        if m_lin:
            neighbors.append({"ip": m_lin.group(1), "iface": m_lin.group(2), "mac": normalize_mac(m_lin.group(3)), "state": m_lin.group(4), "raw": line})
            continue
        # macOS arp: ? (192.168.1.1) at aa:bb:... on en0 ifscope [ethernet]
        m_mac = re.match(r"^\S+\s+\((\d+\.\d+\.\d+\.\d+)\)\s+at\s+([0-9a-f:]{17})\s+on\s+(\S+)", line, re.I)
        if m_mac:
            neighbors.append({"ip": m_mac.group(1), "mac": normalize_mac(m_mac.group(2)), "iface": m_mac.group(3), "raw": line})
            continue

    gateway_mac = None
    return {
        "arp_neighbor_raw": raw,
        "neighbor_count_estimate": len(neighbors),
        "known_neighbors": neighbors,
        "gateway_mac": gateway_mac,
        "tool_output": n,
    }


def collect_dns() -> Dict[str, Any]:
    data = {"dns_servers": [], "search_domains": [], "raw": "", "tool_output": {}}

    if is_linux():
        r = run_cmd(["sh", "-lc", "cat /etc/resolv.conf 2>/dev/null | sed -n '1,200p'"])
        data["tool_output"]["resolv_conf"] = r
        raw = r.get("stdout", "")
        data["raw"] = raw
        for line in raw.splitlines():
            line = line.strip()
            if line.startswith("nameserver"):
                parts = line.split()
                if len(parts) >= 2:
                    data["dns_servers"].append(parts[1])
            if line.startswith("search"):
                data["search_domains"].extend(line.split()[1:])

    elif is_macos():
        r = run_cmd(["sh", "-lc", "scutil --dns | sed -n '1,240p'"])
        data["tool_output"]["scutil_dns"] = r
        data["raw"] = r.get("stdout", "")

    elif is_windows():
        r = run_cmd(["cmd", "/c", "ipconfig /all"])
        data["tool_output"]["ipconfig_all"] = r
        data["raw"] = (r.get("stdout") or "")[:4000]

    # simple DNS tests using system resolver (no scanning)
    def dns_lookup(host: str) -> Dict[str, Any]:
        t0 = time.time()
        try:
            infos = socket.getaddrinfo(host, 443)
            dt_ms = int((time.time() - t0) * 1000)
            addrs = sorted({i[4][0] for i in infos})
            return {"ok": True, "host": host, "addrs": addrs, "latency_ms": dt_ms}
        except Exception as e:
            return {"ok": False, "host": host, "error": str(e)}

    data["dns_test_google"] = dns_lookup("google.com")
    data["dns_test_cloudflare"] = dns_lookup("cloudflare.com")

    return data


def collect_wifi() -> Dict[str, Any]:
    data = {
        "wifi_connected": None,
        "wifi_ssid": None,
        "wifi_bssid": None,
        "wifi_signal": None,
        "wifi_channel": None,
        "wifi_frequency": None,
        "wifi_security": None,
        "wifi_interface_name": None,
        "tool_raw": "",
        "tool_output": {},
    }

    if is_windows():
        r = run_cmd(["cmd", "/c", "netsh wlan show interfaces"])
        data["tool_output"]["netsh_wlan_show_interfaces"] = r
        raw = r.get("stdout", "")
        data["tool_raw"] = raw
        # minimal parsing
        m = re.search(r"^\s*SSID\s*:\s*(.+)$", raw, re.M)
        if m:
            data["wifi_ssid"] = m.group(1).strip()
            data["wifi_connected"] = True
        m = re.search(r"^\s*BSSID\s*:\s*(.+)$", raw, re.M)
        if m:
            data["wifi_bssid"] = m.group(1).strip()
        m = re.search(r"^\s*Signal\s*:\s*(.+)$", raw, re.M)
        if m:
            data["wifi_signal"] = m.group(1).strip()

    elif is_macos():
        airport = "/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport"
        if os.path.exists(airport):
            r = run_cmd([airport, "-I"])
            data["tool_output"]["airport_I"] = r
            raw = r.get("stdout", "")
            data["tool_raw"] = raw
            # parse common keys
            def grab(key: str) -> Optional[str]:
                m = re.search(rf"^\s*{re.escape(key)}:\s*(.+)$", raw, re.M)
                return m.group(1).strip() if m else None
            data["wifi_ssid"] = grab("SSID")
            data["wifi_bssid"] = grab("BSSID")
            data["wifi_signal"] = grab("agrCtlRSSI")
            data["wifi_channel"] = grab("channel")
            data["wifi_connected"] = bool(data["wifi_ssid"])
        else:
            data["tool_raw"] = "airport tool not found"

    elif is_linux():
        if which("nmcli"):
            r = run_cmd(["sh", "-lc", "nmcli -t -f ACTIVE,SSID,BSSID,DEVICE,CHAN,FREQ,SIGNAL,SECURITY dev wifi 2>/dev/null | head -n 40"])
            data["tool_output"]["nmcli_wifi"] = r
            raw = r.get("stdout", "")
            data["tool_raw"] = raw
            # find ACTIVE:yes line
            for line in raw.splitlines():
                parts = line.split(":")
                if parts and parts[0] == "yes":
                    # yes:SSID:BSSID:DEVICE:CHAN:FREQ:SIGNAL:SECURITY
                    data["wifi_connected"] = True
                    if len(parts) > 1: data["wifi_ssid"] = parts[1] or None
                    if len(parts) > 2: data["wifi_bssid"] = parts[2] or None
                    if len(parts) > 3: data["wifi_interface_name"] = parts[3] or None
                    if len(parts) > 4: data["wifi_channel"] = parts[4] or None
                    if len(parts) > 5: data["wifi_frequency"] = parts[5] or None
                    if len(parts) > 6: data["wifi_signal"] = parts[6] or None
                    if len(parts) > 7: data["wifi_security"] = parts[7] or None
                    break
            if data["wifi_connected"] is None:
                data["wifi_connected"] = False

    return data


def collect_local_ports() -> Dict[str, Any]:
    listeners = []
    def pname(pid: Optional[int]) -> str:
        if not pid:
            return "unknown"
        try:
            return psutil.Process(pid).name()
        except Exception:
            return "unknown"

    for c in psutil.net_connections(kind="tcp"):
        if c.status == psutil.CONN_LISTEN and c.laddr:
            ip = getattr(c.laddr, "ip", c.laddr[0])
            port = getattr(c.laddr, "port", c.laddr[1])
            listeners.append({"proto": "tcp", "local": f"{ip}:{port}", "pid": c.pid, "process": pname(c.pid)})

    udp_binds = []
    for c in psutil.net_connections(kind="udp"):
        if c.laddr:
            ip = getattr(c.laddr, "ip", c.laddr[0])
            port = getattr(c.laddr, "port", c.laddr[1])
            udp_binds.append({"proto": "udp", "local": f"{ip}:{port}", "pid": c.pid, "process": pname(c.pid)})

    privileged = [x for x in listeners if safe_int(x["local"].rsplit(":", 1)[-1]) is not None and int(x["local"].rsplit(":", 1)[-1]) < 1024]

    return {
        "local_listeners_count": len(listeners),
        "tcp_listeners": sorted(listeners, key=lambda x: x["local"]),
        "udp_binds": sorted(udp_binds, key=lambda x: x["local"]),
        "privileged_ports_listening": privileged,
        "socket_count": len(listeners) + len(udp_binds),
    }


def collect_firewall() -> Dict[str, Any]:
    data = {"firewall_enabled": None, "tool_raw": "", "tool_output": {}}

    if is_windows():
        r = run_cmd(["cmd", "/c", "netsh advfirewall show allprofiles"])
        data["tool_output"]["netsh_advfirewall"] = r
        raw = r.get("stdout", "")
        data["tool_raw"] = raw[:4000]
        data["firewall_enabled"] = ("State" in raw and "ON" in raw)

    elif is_macos():
        r = run_cmd(["sh", "-lc", "/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate 2>/dev/null"])
        data["tool_output"]["socketfilterfw"] = r
        data["tool_raw"] = r.get("stdout", "")
        data["firewall_enabled"] = ("enabled" in (data["tool_raw"] or "").lower())

    elif is_linux():
        if which("ufw"):
            r = run_cmd(["sh", "-lc", "ufw status verbose 2>/dev/null"])
            data["tool_output"]["ufw_status"] = r
            data["tool_raw"] = r.get("stdout", "")
            data["firewall_enabled"] = ("Status: active" in (data["tool_raw"] or ""))
        elif which("firewall-cmd"):
            r = run_cmd(["sh", "-lc", "firewall-cmd --state 2>/dev/null"])
            data["tool_output"]["firewall_cmd_state"] = r
            data["tool_raw"] = r.get("stdout", "")
            data["firewall_enabled"] = ("running" in (data["tool_raw"] or ""))
        else:
            data["tool_raw"] = "No ufw/firewalld tooling found"

    return data


# ----------------------- WAN collectors (no LAN scanning) -----------------------

def collect_public_ip() -> Dict[str, Any]:
    if requests is None:
        return {"ok": False, "error": "requests not installed", "public_ip": None, "source": None}
    sources = [
        ("ipify", "https://api.ipify.org?format=json"),
        ("ifconfig.me", "https://ifconfig.me/ip"),
    ]
    for name, url in sources:
        try:
            r = requests.get(url, timeout=6, headers={"User-Agent": "net-inventory/1.0"})
            if r.status_code == 200:
                text = r.text.strip()
                ip = None
                if text.startswith("{"):
                    ip = json.loads(text).get("ip")
                else:
                    ip = text
                return {"ok": True, "public_ip": ip, "source": name}
        except Exception as e:
            last_err = str(e)
    return {"ok": False, "error": last_err if "last_err" in locals() else "unknown", "public_ip": None, "source": None}


def collect_traceroute(enabled: bool) -> Dict[str, Any]:
    if not enabled:
        return {"enabled": False}
    target = "1.1.1.1"
    if is_windows():
        cmd = ["cmd", "/c", f"tracert -d {target}"]
    else:
        if which("traceroute"):
            cmd = ["sh", "-lc", f"traceroute -n -m 20 {target} 2>/dev/null"]
        else:
            return {"enabled": True, "ok": False, "error": "traceroute not found"}
    r = run_cmd(cmd, timeout=25, limit=80_000)
    return {"enabled": True, "ok": r.get("ok"), "raw": r.get("stdout", ""), "tool_output": r}


def collect_connectivity() -> Dict[str, Any]:
    # simple TCP connect tests (no LAN scanning)
    tests = []
    for host, port in [("1.1.1.1", 53), ("8.8.8.8", 53), ("cloudflare.com", 443)]:
        t0 = time.time()
        ok = False
        err = None
        try:
            with socket.create_connection((host, port), timeout=3):
                ok = True
        except Exception as e:
            err = str(e)
        tests.append({
            "host": host,
            "port": port,
            "ok": ok,
            "latency_ms": int((time.time() - t0) * 1000),
            "error": err,
        })
    return {"tests": tests}


# ----------------------- UPnP IGD (port mappings only) -----------------------

def collect_upnp_mappings(enabled: bool) -> Dict[str, Any]:
    if not enabled:
        return {"enabled": False}

    if miniupnpc is None:
        return {"enabled": True, "ok": False, "error": "miniupnpc not installed", "mappings": []}

    try:
        u = miniupnpc.UPnP()
        u.discoverdelay = 200
        n = u.discover()
        u.selectigd()
        mappings = []
        i = 0
        while True:
            try:
                m = u.getgenericportmapping(i)
                if not m:
                    break
                # (extPort, protocol, intClient, intPort, desc, enabled, leaseDuration)
                mappings.append({
                    "external_port": m[0],
                    "protocol": m[1],
                    "internal_client": m[2],
                    "internal_port": m[3],
                    "description": m[4],
                    "enabled": m[5],
                    "lease_duration": m[6],
                })
                i += 1
                if i > 5000:
                    break
            except Exception:
                break

        dev = {
            "discover_count": n,
            "igd_lanaddr": getattr(u, "lanaddr", None),
            "external_ip": None,
        }
        try:
            dev["external_ip"] = u.externalipaddress()
        except Exception:
            pass

        return {"enabled": True, "ok": True, "device": dev, "mappings": mappings, "count": len(mappings)}
    except Exception as e:
        return {"enabled": True, "ok": False, "error": str(e), "mappings": []}


# ----------------------- report assembly -----------------------

def build_report(args: argparse.Namespace) -> Dict[str, Any]:
    report: Dict[str, Any] = {}

    report["system"] = collect_system()
    report["interfaces"] = collect_interfaces()
    report["routing"] = collect_routing()
    report["neighbors"] = collect_neighbors()
    report["dns"] = collect_dns()
    report["wifi"] = collect_wifi()
    report["local_ports"] = collect_local_ports()
    report["firewall"] = collect_firewall()

    # WAN
    report["wan_connectivity"] = collect_connectivity()
    report["public_ip"] = collect_public_ip() if args.public_ip else {"enabled": False}
    report["traceroute"] = collect_traceroute(args.traceroute)

    # Router tables via exports
    report["router_tables"] = {
        "dhcp_leases": parse_dhcp_leases(args.dhcp),
        "clients_lan": parse_clients(args.clients_lan, "lan"),
        "clients_wifi": parse_clients(args.clients_wifi, "wifi"),
        "port_forwarding": parse_port_forwards(args.portfw),
    }

    # UPnP (standard, no scanning)
    report["upnp"] = collect_upnp_mappings(args.upnp)

    # Flatten/extra summary keys to help reach “100+ parameters”
    summary = {}
    summary["default_gateway_ip"] = report["routing"].get("default_gateway_ip")
    summary["iface_count"] = report["interfaces"].get("iface_count")
    summary["neighbor_count_estimate"] = report["neighbors"].get("neighbor_count_estimate")
    summary["local_listeners_count"] = report["local_ports"].get("local_listeners_count")
    summary["dhcp_lease_count"] = report["router_tables"]["dhcp_leases"].get("lease_count")
    summary["upnp_mapping_count"] = report["upnp"].get("count") if isinstance(report["upnp"], dict) else None
    report["summary"] = summary

    return report


def main():
    ap = argparse.ArgumentParser(description="Safe 100+ parameter network inventory (no LAN scanning).")
    ap.add_argument("--out", default="", help="Write JSON report to file (else prints).")

    # WAN options
    ap.add_argument("--public-ip", action="store_true", help="Query public IP (uses external HTTPS service).")
    ap.add_argument("--traceroute", action="store_true", help="Run traceroute to 1.1.1.1 (no LAN scanning).")

    # Router export inputs
    ap.add_argument("--dhcp", default="", help="Path to DHCP leases CSV export.")
    ap.add_argument("--clients-lan", default="", help="Path to LAN clients CSV export.")
    ap.add_argument("--clients-wifi", default="", help="Path to Wi-Fi clients CSV export.")
    ap.add_argument("--portfw", default="", help="Path to port forwarding rules CSV export.")

    # UPnP
    ap.add_argument("--upnp", action="store_true", help="Query UPnP IGD for port mappings (if enabled on router).")

    args = ap.parse_args()

    report = build_report(args)
    text = json.dumps(report, indent=2)

    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            f.write(text)
        print(f"Wrote report: {args.out}")
    else:
        print(text)


if __name__ == "__main__":
    main()
