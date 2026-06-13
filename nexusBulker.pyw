#!/usr/bin/env python3
"""
V2Ray & Clash Config Bulk Renamer Studio (Geo-Analytics Edition)
An elegant, production-grade PySide6 application to import, parse, rename, filter,
and update V2Ray URIs and Clash YAML configurations with deep Geo-IP analysis.
"""

import sys
import os
import re
import json
import base64
import urllib.parse
import urllib.request
import random
import socket
import ssl
import subprocess
import tempfile
import time
import threading
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
import yaml  # PyYAML dependency for parsing Clash formats safely
from PySide6.QtCore import Qt, QSize, Signal, Slot, QThread
from PySide6.QtGui import QFont, QIcon, QTextCursor, QColor, QPalette, QIntValidator
from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QSplitter, QTextEdit, QLineEdit, QPushButton, QLabel, QTableWidget,
    QTableWidgetItem, QHeaderView, QGroupBox, QFileDialog, QFormLayout,
    QMessageBox, QFrame, QScrollArea, QGridLayout, QCheckBox, QToolButton,
    QProgressBar, QComboBox, QSizePolicy
)

# --- Standard Assets & Pools ---
EMOJIS = [
    "⚡"
]

HEARTS = [
    "❤️", "🩷", "🧡", "💛", "💚", "💙", "🩵", "💜", "🤎", "🖤", "🩶", "🤍", "❣️", "💕", "💞", "💓", "💗", "💖", "💝", "❤️"
]

APP_HELP_TEXT = """📌 Quick Tags Guide:
• <num>, <num:2> : Numbering (1, 01...)
• <emoji>, <heart>: Unique random icons
• <flag>         : Country Flag Emoji
• <country>      : Country Name
• <city>         : City Name
• <asn>          : ISP / ASN Data
• <protocol>     : Node Protocol (vmess, etc)
• <ping>         : Ping (ms)
"""


# --- Core Configuration Processor Class ---
class ConfigItem:
    def __init__(self, raw_data: str, index: int, config_type: str = "URI"):
        self.raw_data = raw_data.strip()
        self.index = index
        self.config_type = config_type
        self.protocol = "Unknown"
        self.original_name = f"Node_{index}"
        self.current_host = ""
        self.current_port = ""
        self.auth_id = ""  # Used to identify duplicates via UUID/Password
        
        self.clash_dict = None
        self.uri_parsed = None
        self.parse()

    def parse(self):
        if not self.raw_data:
            return

        if isinstance(self.raw_data, dict):
            self.config_type = "CLASH_DICT"
            self.clash_dict = self.raw_data
            self.protocol = self.clash_dict.get("type", "Clash")
            self.original_name = self.clash_dict.get("name", f"ClashNode_{self.index}")
            self.current_host = str(self.clash_dict.get("server", ""))
            self.current_port = str(self.clash_dict.get("port", ""))
            self.auth_id = str(self.clash_dict.get("uuid", self.clash_dict.get("password", "")))
            return

        stripped = self.raw_data.strip()
        if stripped.startswith("{") or (":" in stripped and not "://" in stripped):
            self.protocol = "YAML/JSON Chunk"
            return

        if "://" in stripped:
            parts = stripped.split("://", 1)
            self.protocol = parts[0].lower()
            payload = parts[1]

            if self.protocol == "vmess":
                try:
                    clean_payload = payload.split("#")[0]
                    padded = clean_payload + "=" * ((4 - len(clean_payload) % 4) % 4)
                    decoded = base64.b64decode(padded).decode('utf-8')
                    js = json.loads(decoded)
                    self.original_name = js.get("ps", f"VMess_{self.index}")
                    self.current_host = js.get("add", "")
                    self.current_port = str(js.get("port", ""))
                    self.auth_id = str(js.get("id", ""))
                    self.uri_parsed = js
                except Exception:
                    if "#" in payload:
                        self.original_name = urllib.parse.unquote(payload.split("#")[-1])

            elif self.protocol in ["vless", "trojan", "ss", "ssr", "hysteria", "hy2", "hysteria2"]:
                if "#" in payload:
                    main_part, name_part = payload.rsplit("#", 1)
                    self.original_name = urllib.parse.unquote(name_part)
                else:
                    main_part = payload
                
                try:
                    user_info_split = main_part.split("@")
                    if len(user_info_split) > 1:
                        self.auth_id = user_info_split[0]
                        address_part = user_info_split[-1]
                    else:
                        address_part = user_info_split[0]

                    address_clean = address_part.split("?")[0]
                    if ":" in address_clean:
                        h, p = address_clean.rsplit(":", 1)
                        self.current_host = h
                        self.current_port = p
                except Exception:
                    pass

    def get_updated_data(self, new_name: str, force_host: str = "", force_port: str = "") -> str:
        try:
            if self.config_type == "CLASH_DICT" and self.clash_dict:
                updated_dict = self.clash_dict.copy()
                updated_dict["name"] = new_name
                if force_host: updated_dict["server"] = force_host
                if force_port:
                    try: updated_dict["port"] = int(force_port)
                    except ValueError: updated_dict["port"] = force_port
                return updated_dict

            stripped = self.raw_data.strip()
            if "://" not in stripped: return stripped

            parts = stripped.split("://", 1)
            proto = parts[0].lower()
            payload = parts[1]

            if proto == "vmess":
                if isinstance(self.uri_parsed, dict):
                    updated_js = self.uri_parsed.copy()
                    updated_js["ps"] = new_name
                    if force_host: updated_js["add"] = force_host
                    if force_port: updated_js["port"] = force_port
                    serialized = json.dumps(updated_js, ensure_ascii=False)
                    b64_encoded = base64.b64encode(serialized.encode('utf-8')).decode('utf-8')
                    return f"vmess://{b64_encoded}"
                else:
                    clean_payload = payload.split("#")[0]
                    return f"vmess://{clean_payload}#{urllib.parse.quote(new_name)}"

            elif proto in ["vless", "trojan", "ss", "ssr", "hysteria", "hy2", "hysteria2"]:
                main_part = payload.rsplit("#", 1)[0] if "#" in payload else payload
                if force_host or force_port:
                    try:
                        if "@" in main_part:
                            user_info, endpoint = main_part.split("@", 1)
                            prefix = user_info + "@"
                        else:
                            endpoint = main_part
                            prefix = ""
                        if "?" in endpoint:
                            address_block, params = endpoint.split("?", 1)
                            suffix = "?" + params
                        else:
                            address_block = endpoint
                            suffix = ""
                        if ":" in address_block:
                            h_part, p_part = address_block.rsplit(":", 1)
                            h_part = force_host if force_host else h_part
                            p_part = force_port if force_port else p_part
                            address_block = f"{h_part}:{p_part}"
                        main_part = f"{prefix}{address_block}{suffix}"
                    except Exception:
                        pass
                return f"{proto}://{main_part}#{urllib.parse.quote(new_name)}"

        except Exception:
            return self.raw_data


# --- Effective Config Variant (Bulk Overrides) ---
class ConfigVariant:
    def __init__(self, base: ConfigItem, force_host: str = "", force_port: str = ""):
        self.base = base
        self.index = base.index
        self.config_type = base.config_type
        self.protocol = base.protocol
        self.original_name = base.original_name
        self.auth_id = base.auth_id
        self.raw_data = base.raw_data
        self.clash_dict = base.clash_dict
        self.uri_parsed = base.uri_parsed
        self.force_host = force_host.strip() if force_host else ""
        self.force_port = force_port.strip() if force_port else ""
        self.effective_host = self.force_host if self.force_host else base.current_host
        self.effective_port = self.force_port if self.force_port else base.current_port

    def get_updated_data(self, new_name: str, force_host: str = "", force_port: str = "") -> str:
        return self.base.get_updated_data(new_name, self.force_host, self.force_port)


def decode_http_chunked_body(body_bytes: bytes) -> bytes:
    out = bytearray()
    i = 0
    ln = len(body_bytes)
    while i < ln:
        j = body_bytes.find(b"\r\n", i)
        if j == -1:
            break
        size_line = body_bytes[i:j].split(b";", 1)[0].strip()
        try:
            size = int(size_line.decode("ascii"), 16)
        except Exception:
            break
        i = j + 2
        if size == 0:
            break
        out.extend(body_bytes[i:i + size])
        i += size + 2
    return bytes(out)


def socks5_open_connection(proxy_host: str, proxy_port: int, dest_host: str, dest_port: int, timeout: float):
    s = socket.create_connection((proxy_host, int(proxy_port)), timeout=timeout)
    s.settimeout(timeout)
    s.sendall(b"\x05\x01\x00")
    resp = s.recv(2)
    if len(resp) != 2 or resp[0] != 5 or resp[1] != 0:
        s.close()
        raise RuntimeError("SOCKS5 handshake failed")

    host_bytes = dest_host.encode("utf-8")
    if len(host_bytes) > 255:
        s.close()
        raise RuntimeError("SOCKS5 host too long")

    req = b"\x05\x01\x00\x03" + bytes([len(host_bytes)]) + host_bytes + int(dest_port).to_bytes(2, "big")
    s.sendall(req)
    rep = s.recv(4)
    if len(rep) != 4 or rep[0] != 5 or rep[1] != 0:
        s.close()
        raise RuntimeError("SOCKS5 connect failed")

    atyp = rep[3]
    if atyp == 1:
        s.recv(4)
    elif atyp == 3:
        l = s.recv(1)
        if l:
            s.recv(l[0])
    elif atyp == 4:
        s.recv(16)
    s.recv(2)
    return s


def http_get_json_via_socks(url: str, proxy_host: str, proxy_port: int, timeout: float = 4.0):
    u = urllib.parse.urlsplit(url)
    host = u.hostname or ""
    scheme = (u.scheme or "https").lower()
    port = u.port or (443 if scheme == "https" else 80)
    path = u.path or "/"
    if u.query:
        path += "?" + u.query

    sock = socks5_open_connection(proxy_host, proxy_port, host, port, timeout)
    try:
        if scheme == "https":
            ctx = ssl.create_default_context()
            sock = ctx.wrap_socket(sock, server_hostname=host)

        req = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"User-Agent: Mozilla/5.0\r\n"
            f"Accept: application/json\r\n"
            f"Connection: close\r\n\r\n"
        ).encode("utf-8")
        sock.sendall(req)

        buf = bytearray()
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            buf.extend(chunk)

        raw = bytes(buf)
        split_at = raw.find(b"\r\n\r\n")
        if split_at == -1:
            return None

        header_bytes = raw[:split_at].lower()
        body = raw[split_at + 4:]
        if b"transfer-encoding: chunked" in header_bytes:
            body = decode_http_chunked_body(body)

        try:
            return json.loads(body.decode("utf-8", errors="ignore"))
        except Exception:
            return None
    finally:
        try:
            sock.close()
        except Exception:
            pass


def build_singbox_outbound(config: ConfigItem):
    try:
        if config.config_type == "CLASH_DICT" and isinstance(config.clash_dict, dict):
            cd = config.clash_dict
            proto = str(cd.get("type", "")).lower()
            server = str(cd.get("server", "")).strip()
            port = int(cd.get("port", 0))
            if not server or not port:
                return None

            if proto == "vmess":
                return {
                    "type": "vmess",
                    "tag": "out",
                    "server": server,
                    "server_port": port,
                    "uuid": str(cd.get("uuid", "")).strip(),
                    "security": "auto",
                    "alter_id": int(cd.get("alterId", cd.get("alter_id", 0)) or 0)
                }
            if proto == "vless":
                tls_enabled = bool(cd.get("tls", False))
                outbound = {
                    "type": "vless",
                    "tag": "out",
                    "server": server,
                    "server_port": port,
                    "uuid": str(cd.get("uuid", "")).strip()
                }
                if tls_enabled:
                    outbound["tls"] = {"enabled": True, "server_name": str(cd.get("servername", cd.get("sni", "")) or server), "insecure": True}
                return outbound
            if proto == "trojan":
                outbound = {
                    "type": "trojan",
                    "tag": "out",
                    "server": server,
                    "server_port": port,
                    "password": str(cd.get("password", "")).strip()
                }
                outbound["tls"] = {"enabled": True, "server_name": str(cd.get("sni", "") or server), "insecure": True}
                return outbound
            if proto in ("ss", "shadowsocks"):
                return {
                    "type": "shadowsocks",
                    "tag": "out",
                    "server": server,
                    "server_port": port,
                    "method": str(cd.get("cipher", cd.get("method", ""))).strip(),
                    "password": str(cd.get("password", "")).strip()
                }
            if proto in ("hysteria2", "hy2"):
                outbound = {
                    "type": "hysteria2",
                    "tag": "out",
                    "server": server,
                    "server_port": port,
                    "password": str(cd.get("password", cd.get("auth", ""))).strip()
                }
                outbound["tls"] = {"enabled": True, "server_name": str(cd.get("sni", "") or server), "insecure": True}
                return outbound
            if proto == "hysteria":
                outbound = {
                    "type": "hysteria",
                    "tag": "out",
                    "server": server,
                    "server_port": port,
                    "auth_str": str(cd.get("auth-str", cd.get("auth_str", cd.get("auth", "")))).strip()
                }
                outbound["tls"] = {"enabled": True, "server_name": str(cd.get("sni", "") or server), "insecure": True}
                return outbound
            return None

        raw = str(config.raw_data).strip()
        if "://" not in raw:
            return None

        proto = raw.split("://", 1)[0].lower()
        if proto == "vmess" and isinstance(config.uri_parsed, dict):
            js = config.uri_parsed
            server = str(js.get("add", "")).strip()
            port = int(js.get("port", 0))
            if not server or not port:
                return None
            outbound = {
                "type": "vmess",
                "tag": "out",
                "server": server,
                "server_port": port,
                "uuid": str(js.get("id", "")).strip(),
                "security": "auto",
                "alter_id": int(js.get("aid", 0) or 0)
            }
            tls_val = str(js.get("tls", "")).lower()
            if tls_val in ("tls", "1", "true"):
                outbound["tls"] = {"enabled": True, "server_name": str(js.get("sni", js.get("host", "")) or server), "insecure": True}
            net = str(js.get("net", "tcp")).lower()
            if net == "ws":
                outbound["transport"] = {"type": "ws", "path": str(js.get("path", "/") or "/"), "headers": {"Host": str(js.get("host", ""))}}
            if net == "grpc":
                outbound["transport"] = {"type": "grpc", "service_name": str(js.get("path", ""))}
            return outbound

        u = urllib.parse.urlsplit(raw)
        host = u.hostname or ""
        port = u.port or 0
        if not host or not port:
            return None
        q = urllib.parse.parse_qs(u.query)

        if proto == "vless":
            outbound = {"type": "vless", "tag": "out", "server": host, "server_port": int(port), "uuid": urllib.parse.unquote(u.username or "")}
            sec = (q.get("security", [""])[0] or "").lower()
            tls_enabled = sec == "tls" or (q.get("tls", [""])[0] or "").lower() in ("1", "true")
            if tls_enabled:
                outbound["tls"] = {"enabled": True, "server_name": q.get("sni", [""])[0] or q.get("host", [""])[0] or host, "insecure": True}
            t = (q.get("type", ["tcp"])[0] or "tcp").lower()
            if t == "ws":
                outbound["transport"] = {"type": "ws", "path": q.get("path", ["/"])[0] or "/", "headers": {"Host": q.get("host", [""])[0]}}
            if t == "grpc":
                outbound["transport"] = {"type": "grpc", "service_name": q.get("serviceName", [""])[0] or q.get("service_name", [""])[0]}
            flow = q.get("flow", [""])[0]
            if flow:
                outbound["flow"] = flow
            return outbound

        if proto == "trojan":
            outbound = {"type": "trojan", "tag": "out", "server": host, "server_port": int(port), "password": urllib.parse.unquote(u.username or "")}
            outbound["tls"] = {"enabled": True, "server_name": q.get("sni", [""])[0] or q.get("host", [""])[0] or host, "insecure": True}
            return outbound

        if proto in ("hysteria2", "hy2"):
            outbound = {"type": "hysteria2", "tag": "out", "server": host, "server_port": int(port), "password": urllib.parse.unquote(u.username or "")}
            sni = q.get("sni", [""])[0] or host
            insecure = (q.get("insecure", [""])[0] or "").lower() in ("1", "true")
            outbound["tls"] = {"enabled": True, "server_name": sni, "insecure": insecure}
            return outbound

        if proto == "hysteria":
            outbound = {"type": "hysteria", "tag": "out", "server": host, "server_port": int(port), "auth_str": urllib.parse.unquote(u.username or "")}
            sni = q.get("sni", [""])[0] or host
            insecure = (q.get("insecure", [""])[0] or "").lower() in ("1", "true")
            outbound["tls"] = {"enabled": True, "server_name": sni, "insecure": insecure}
            return outbound

        if proto in ("ss", "shadowsocks"):
            method = ""
            password = ""
            if u.username and u.password:
                method = urllib.parse.unquote(u.username)
                password = urllib.parse.unquote(u.password)
            else:
                payload = raw.split("://", 1)[1]
                payload = payload.split("#", 1)[0]
                payload = payload.split("?", 1)[0]
                if "@" in payload:
                    left, right = payload.split("@", 1)
                    if ":" not in left:
                        padded = left + "=" * ((4 - len(left) % 4) % 4)
                        try:
                            decoded = base64.urlsafe_b64decode(padded.encode("utf-8")).decode("utf-8", errors="ignore")
                            if ":" in decoded:
                                method, password = decoded.split(":", 1)
                        except Exception:
                            pass
                    else:
                        method, password = left.split(":", 1)
                    if ":" in right:
                        host = right.rsplit(":", 1)[0]
                        port = int(right.rsplit(":", 1)[1])

            if not method or password is None:
                return None

            return {"type": "shadowsocks", "tag": "out", "server": host, "server_port": int(port), "method": method, "password": password}
    except Exception:
        return None


class SingBoxSocksProxy:
    def __init__(self, singbox_path: str, outbound: dict, socks_port: int):
        self.singbox_path = singbox_path
        self.outbound = outbound
        self.socks_port = int(socks_port)
        self.proc = None
        self.cfg_path = None

    def start(self):
        if not self.singbox_path or not os.path.exists(self.singbox_path):
            return False
        if not isinstance(self.outbound, dict):
            return False

        cfg = {
            "log": {"disabled": True},
            "inbounds": [{"type": "socks", "tag": "in", "listen": "127.0.0.1", "listen_port": self.socks_port}],
            "outbounds": [
                self.outbound,
                {"type": "direct", "tag": "direct"},
                {"type": "block", "tag": "block"}
            ],
            "route": {"rules": [{"inbound": ["in"], "outbound": "out"}], "final": "direct"}
        }

        fd, path = tempfile.mkstemp(prefix="nexusbulker_singbox_", suffix=".json")
        os.close(fd)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(cfg, f, ensure_ascii=False)
        self.cfg_path = path

        creationflags = subprocess.CREATE_NO_WINDOW if hasattr(subprocess, "CREATE_NO_WINDOW") else 0
        self.proc = subprocess.Popen([self.singbox_path, "run", "-c", self.cfg_path], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, creationflags=creationflags)

        deadline = time.time() + 4.0
        while time.time() < deadline:
            try:
                with socket.create_connection(("127.0.0.1", self.socks_port), timeout=0.5):
                    return True
            except Exception:
                time.sleep(0.1)
        return False

    def stop(self):
        if self.proc:
            try:
                self.proc.terminate()
                self.proc.wait(timeout=2)
            except Exception:
                try:
                    self.proc.kill()
                except Exception:
                    pass
        self.proc = None
        if self.cfg_path and os.path.exists(self.cfg_path):
            try:
                os.remove(self.cfg_path)
            except Exception:
                pass
        self.cfg_path = None


# --- Background Worker Thread for Deep Processing & Geo Analytics ---
class ProcessWorker(QThread):
    progress_update = Signal(dict)
    log_msg = Signal(str, str)
    finished_data = Signal(dict)
    
    def __init__(self, configs, params):
        super().__init__()
        self.configs = configs
        self.params = params
        self._is_running = True
        self.cache = {}
        self.cache_lock = threading.Lock()
        self.geo_proxy = None
        
        # Telemetry storage
        self.stats = {
            "alive": 0, "dead": 0,
            "known_loc": 0, "unknown_loc": 0,
            "api_usage": {p: 0 for p in [
                "freeipapi.com", "ip-api.com", "geojs.io", "ipwho.is", 
                "ipapi.co", "api.techniknews.net", "api.ipapi.is"
            ]},
            "bytes_used": 0
        }
        self.stats_lock = threading.Lock()
        self.start_time = 0

    def http_get_json(self, url: str):
        try:
            if self.geo_proxy:
                return http_get_json_via_socks(url, "127.0.0.1", self.geo_proxy.socks_port, timeout=4.0)
            req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
            with urllib.request.urlopen(req, timeout=3) as response:
                return json.loads(response.read().decode())
        except Exception:
            return None

    def stop(self):
        self._is_running = False

    def tcping(self, host, port, timeout=2.0):
        if not port: port = 80
        with self.stats_lock:
            self.stats["bytes_used"] += 250  # Mock TCP connection bytes (SYN/ACK sequence)
            
        start = time.time()
        try:
            with socket.create_connection((host, int(port)), timeout=timeout):
                return int((time.time() - start) * 1000)
        except Exception:
            return -1

    def get_flag(self, code):
        if code and len(code) == 2:
            try:
                return chr(ord(code[0].upper()) + 127397) + chr(ord(code[1].upper()) + 127397)
            except Exception:
                pass
        return "🏳️"

    def fetch_geo_from_provider(self, ip, prov):
        """Fetches Geo Data from a specific provider."""
        with self.stats_lock:
            self.stats["api_usage"][prov] += 1
            self.stats["bytes_used"] += 1500  # Mock HTTP Payload size
            
        res = {"country": "Unknown", "city": "Unknown", "asn": "Unknown", "flag": "🏳️", "success": False}
        try:
            if prov == "freeipapi.com":
                data = self.http_get_json(f"https://freeipapi.com/api/json/{ip}")
                if data:
                    res["country"] = data.get("countryName", "Unknown")
                    res["city"] = data.get("cityName", "Unknown")
                    res["asn"] = "AS" + str(data.get("asn", "")) if data.get("asn") else "Unknown"
                    res["flag"] = self.get_flag(data.get("countryCode", ""))
                    res["success"] = True
            elif prov == "ip-api.com":
                data = self.http_get_json(f"http://ip-api.com/json/{ip}?fields=status,country,countryCode,city,isp,as")
                if data and data.get("status") == "success":
                    res["country"] = data.get("country", "Unknown")
                    res["city"] = data.get("city", "Unknown")
                    res["asn"] = data.get("as", "").split(" ")[0] if "as" in data else data.get("isp", "Unknown")
                    res["flag"] = self.get_flag(data.get("countryCode", ""))
                    res["success"] = True
            elif prov == "geojs.io":
                data = self.http_get_json(f"https://get.geojs.io/v1/ip/geo/{ip}.json")
                if data:
                    res["country"] = data.get("country", "Unknown")
                    res["city"] = data.get("city", "Unknown")
                    org = data.get("organization", "Unknown")
                    res["asn"] = org.split(" ")[0] if org != "Unknown" else "Unknown"
                    res["flag"] = self.get_flag(data.get("country_code", ""))
                    res["success"] = True
            elif prov == "ipwho.is":
                data = self.http_get_json(f"https://ipwho.is/{ip}")
                if data and data.get("success", False):
                    res["country"] = data.get("country", "Unknown")
                    res["city"] = data.get("city", "Unknown")
                    asn = data.get("connection", {}).get("asn", "Unknown")
                    res["asn"] = f"AS{asn}" if asn != "Unknown" else "Unknown"
                    res["flag"] = self.get_flag(data.get("country_code", ""))
                    res["success"] = True
            elif prov == "ipapi.co":
                data = self.http_get_json(f"https://ipapi.co/{ip}/json/")
                if data and "error" not in data:
                    res["country"] = data.get("country_name", "Unknown")
                    res["city"] = data.get("city", "Unknown")
                    res["asn"] = data.get("asn", "Unknown")
                    res["flag"] = self.get_flag(data.get("country_code", ""))
                    res["success"] = True
            elif prov == "api.techniknews.net":
                data = self.http_get_json(f"https://api.techniknews.net/ipgeo/{ip}")
                if data and data.get("status") == "success":
                    res["country"] = data.get("country", "Unknown")
                    res["city"] = data.get("city", "Unknown")
                    res["asn"] = data.get("as", "").split(" ")[0] if "as" in data else data.get("isp", "Unknown")
                    res["flag"] = self.get_flag(data.get("countryCode", ""))
                    res["success"] = True
            elif prov == "api.ipapi.is":
                data = self.http_get_json(f"https://api.ipapi.is/?q={ip}")
                if data and "location" in data:
                    loc = data.get("location", {})
                    res["country"] = loc.get("country", "Unknown")
                    res["city"] = loc.get("city", "Unknown")
                    asn_data = data.get("asn", {})
                    asn_val = asn_data.get("asn", "Unknown") if isinstance(asn_data, dict) else "Unknown"
                    res["asn"] = f"AS{asn_val}" if isinstance(asn_val, int) else str(asn_val)
                    res["flag"] = self.get_flag(loc.get("country_code", ""))
                    res["success"] = True
        except Exception:
            pass
        return res

    def get_geo(self, ip, primary_provider, double_check):
        geo = {"country": "Unknown", "city": "Unknown", "asn": "Unknown", "flag": "🏳️"}
        if not ip: return geo

        # Ordered list of all available providers
        providers = [
            "freeipapi.com", "ip-api.com", "geojs.io", "ipwho.is", 
            "ipapi.co", "api.techniknews.net", "api.ipapi.is"
        ]
        
        # Ensure user's selected primary provider is checked first
        if primary_provider in providers:
            providers.remove(primary_provider)
            providers.insert(0, primary_provider)

        if double_check:
            # Consensus mode: Query all providers and find the most common results
            countries, cities, asns, flags = [], [], [], {}
            for prov in providers:
                res = self.fetch_geo_from_provider(ip, prov)
                if res["success"]:
                    if res["country"] != "Unknown":
                        countries.append(res["country"])
                        flags[res["country"]] = res["flag"]
                    if res["city"] != "Unknown":
                        cities.append(res["city"])
                    if res["asn"] != "Unknown":
                        asns.append(res["asn"])
            
            if countries:
                most_common_country = Counter(countries).most_common(1)[0][0]
                geo["country"] = most_common_country
                geo["flag"] = flags.get(most_common_country, "🏳️")
            if cities:
                geo["city"] = Counter(cities).most_common(1)[0][0]
            if asns:
                geo["asn"] = Counter(asns).most_common(1)[0][0]
        else:
            # Sequential fallback mode: Break when we find the needed location data
            for prov in providers:
                res = self.fetch_geo_from_provider(ip, prov)
                if res["success"]:
                    if res["country"] != "Unknown" and geo["country"] == "Unknown":
                        geo["country"] = res["country"]
                        geo["flag"] = res["flag"]
                    if res["city"] != "Unknown" and geo["city"] == "Unknown":
                        geo["city"] = res["city"]
                    if res["asn"] != "Unknown" and geo["asn"] == "Unknown":
                        geo["asn"] = res["asn"]

                    if geo["country"] != "Unknown" and geo["city"] != "Unknown":
                        break

        return geo

    def process_single(self, idx, config):
        if not self._is_running:
            return None

        eff_host = getattr(config, "effective_host", config.current_host)
        eff_port = getattr(config, "effective_port", config.current_port)
        force_host = getattr(config, "force_host", self.params.get("force_host", ""))
        force_port = getattr(config, "force_port", self.params.get("force_port", ""))
        
        geo_data = {"country": "-", "city": "-", "asn": "-", "flag": "-"}
        ping_ms = 0
        
        if self.params["geo_enabled"]:
            if config.protocol.lower() not in self.params["enabled_protos"] and "clash" not in config.protocol.lower():
                return None
            
            cache_key = f"{eff_host}:{eff_port}"
            with self.cache_lock:
                cached = self.cache.get(cache_key)
            
            if not cached:
                try: ip = socket.gethostbyname(eff_host)
                except Exception: ip = None
                p_res = self.tcping(eff_host, eff_port)
                g_res = self.get_geo(ip, self.params["provider"], self.params["double_check"])
                cached = {"ip": ip, "ping": p_res, "geo": g_res}
                with self.cache_lock:
                    self.cache[cache_key] = cached
            
            ping_ms = cached["ping"]
            geo_data = cached["geo"]
            
            # Telemetry Analytics Processing (Only for ping/geo enabled configs)
            with self.stats_lock:
                if ping_ms != -1: self.stats["alive"] += 1
                else: self.stats["dead"] += 1
                
                if geo_data["country"] != "Unknown" and geo_data["country"] != "-": 
                    self.stats["known_loc"] += 1
                else: 
                    self.stats["unknown_loc"] += 1
            
            loc_filter = self.params["loc_filter"]
            if loc_filter:
                valid_loc = False
                for loc in [l.strip().lower() for l in loc_filter.split(",") if l.strip()]:
                    if loc in geo_data["country"].lower() or loc in geo_data["city"].lower():
                        valid_loc = True
                        break
                if not valid_loc: return None
                    
            ping_filter = self.params["ping_filter"]
            if ping_filter and "-" in ping_filter:
                try:
                    p_min, p_max = map(int, ping_filter.split("-"))
                    if ping_ms < p_min or ping_ms > p_max or ping_ms == -1: return None
                except ValueError: pass
        
        name_instance = self.params["template"]
        name_instance = name_instance.replace("<protocol>", config.protocol.upper())
        name_instance = name_instance.replace("<country>", geo_data["country"])
        name_instance = name_instance.replace("<city>", geo_data["city"])
        name_instance = name_instance.replace("<asn>", geo_data["asn"])
        name_instance = name_instance.replace("<flag>", geo_data["flag"])
        name_instance = name_instance.replace("<ping>", str(ping_ms) if ping_ms != -1 else "Timeout")
        
        num_tags = re.findall(r"<num(?::(\d+))?>", name_instance)
        for tag_spec in num_tags:
            tag_str = "<num>" if not tag_spec else f"<num:{tag_spec}>"
            pad = int(tag_spec) if tag_spec else 1
            name_instance = name_instance.replace(tag_str, str(idx + 1).zfill(pad))

        while "<emoji>" in name_instance: name_instance = name_instance.replace("<emoji>", random.choice(EMOJIS), 1)
        while "<heart>" in name_instance: name_instance = name_instance.replace("<heart>", random.choice(HEARTS), 1)
        
        updated_datum = config.get_updated_data(name_instance, force_host, force_port)
        folder_key = geo_data["country"] if (self.params["geo_enabled"] and self.params["sort_folders"]) else "Default"
        
        return folder_key, updated_datum

    def run(self):
        total = len(self.configs)
        if total == 0:
            self.finished_data.emit({})
            return

        output_results = {}
        self.start_time = time.time()
        processed = 0

        max_w = int(self.params["max_workers"])
        if self.params.get("geo_enabled") and self.params.get("geo_proxy_enabled"):
            base_cfg = self.params.get("proxy_base_config")
            if not base_cfg and self.configs:
                c0 = self.configs[0]
                base_cfg = c0.base if isinstance(c0, ConfigVariant) else c0
            outbound = build_singbox_outbound(base_cfg) if base_cfg else None
            try:
                socks_port = int(self.params.get("proxy_socks_port") or "2080")
            except ValueError:
                socks_port = 2080

            if outbound and self.params.get("singbox_path"):
                self.geo_proxy = SingBoxSocksProxy(self.params.get("singbox_path"), outbound, socks_port)
                if self.geo_proxy.start():
                    self.log_msg.emit(f"Geo Proxy enabled (SOCKS5 127.0.0.1:{socks_port}).", "SUCCESS")
                else:
                    self.geo_proxy = None
                    self.log_msg.emit("Geo Proxy failed to start. Falling back to direct Geo API requests.", "WARN")
            else:
                self.log_msg.emit("Geo Proxy is enabled but no usable node or sing-box path was found. Falling back to direct Geo API requests.", "WARN")

        try:
            with ThreadPoolExecutor(max_workers=max_w) as executor:
                futures = [executor.submit(self.process_single, idx, config) for idx, config in enumerate(self.configs)]
                
                for future in as_completed(futures):
                    if not self._is_running:
                        try: executor.shutdown(wait=False, cancel_futures=True)
                        except TypeError: pass 
                        self.log_msg.emit("Process stopped by user. Saving completed items...", "WARN")
                        break

                    res = future.result()
                    processed += 1
                    
                    if res:
                        folder_key, datum = res
                        if folder_key not in output_results:
                            output_results[folder_key] = []
                        output_results[folder_key].append(datum)
                    
                    elapsed = time.time() - self.start_time
                    rate = processed / elapsed if elapsed > 0 else 0
                    rem_secs = (total - processed) / rate if rate > 0 else 0
                    mins, secs = divmod(int(rem_secs), 60)
                    
                    pct = int((processed / total) * 100)
                    time_str = f"~{mins}m {secs}s remaining" if rem_secs > 0 else "Almost done..."
                    
                    with self.stats_lock:
                        bytes_sec = self.stats["bytes_used"] / elapsed if elapsed > 0 else 0
                        stat_dict = {
                            "current": processed,
                            "total": total,
                            "pct_str": f"{pct}%",
                            "eta_str": time_str,
                            "speed": rate,
                            "alive": self.stats["alive"],
                            "dead": self.stats["dead"],
                            "known_loc": self.stats["known_loc"],
                            "unknown_loc": self.stats["unknown_loc"],
                            "api_usage": self.stats["api_usage"].copy(),
                            "bytes_used": self.stats["bytes_used"],
                            "bytes_sec": bytes_sec
                        }
                    self.progress_update.emit(stat_dict)
        finally:
            if self.geo_proxy:
                try:
                    self.geo_proxy.stop()
                except Exception:
                    pass
                self.geo_proxy = None

        self.finished_data.emit(output_results)


# --- Custom Console Logger ---
class LogConsole(QTextEdit):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setReadOnly(True)
        self.setFont(QFont("Lucida Console", 9))
        self.setStyleSheet("""
            QTextEdit {
                background-color: #0E0F12;
                color: #A0A5B5;
                border: 1px solid #1E222B;
                border-radius: 16px;
            }
        """)

    def log(self, message: str, level: str = "INFO"):
        color_map = {"INFO": "#00FF66", "WARN": "#FFCC00", "ERROR": "#FF3366", "SUCCESS": "#00E5FF"}
        color = color_map.get(level, "#A0A5B5")
        log_html = f'<span style="color: #6272A4;">[Console]</span> <span style="color: {color};">[{level}]</span> {message}'
        self.append(log_html)
        self.moveCursor(QTextCursor.End)


# --- Main Application Frame ---
class App(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("NexusBulker Studio - Geo Edition")
        self.resize(1300, 850)
        self.loaded_configs = []
        self.clash_headers = {}
        self.worker = None
        
        self.setFont(QFont("Calibri", 10))
        self.setup_theme()
        self.init_ui()
        self.console.log("App initialized successfully. Awaiting configurations.", "INFO")

    def setup_theme(self):
        self.setStyleSheet("""
            QMainWindow { background-color: #050607; }
            QWidget { color: #F1F5F9; font-family: "Calibri", "Segoe UI Emoji", "Apple Color Emoji", "Noto Color Emoji", sans-serif; font-size: 13px; }
            QFrame#ControlPanel, QFrame#PreviewPanel { background-color: #0B0D10; border: 1px solid #1F242C; border-radius: 16px; }
            QGroupBox { font-weight: bold; color: #F97316; border: 1px solid #1F242C; border-radius: 16px; margin-top: 12px; padding-top: 16px; }
            QGroupBox::title { subcontrol-origin: margin; left: 10px; padding: 0 5px; }
            
            QPushButton { background-color: #F97316; border: 1px solid #C2410C; border-radius: 16px; color: #0B0D10; font-weight: bold; padding: 8px 16px; }
            QPushButton:hover { background-color: #FB923C; border: 1px solid #EA580C; }
            QPushButton:pressed { background-color: #C2410C; border: 1px solid #9A3412; color: #FFF7ED; }
            QPushButton:disabled { background-color: #1F242C; color: #64748B; border: 1px solid #1F242C; }
            
            QTextEdit, QLineEdit { background-color: #0F1318; border: 1px solid #262B33; border-radius: 16px; color: #F8FAFC; padding: 6px; }
            QTextEdit:focus, QLineEdit:focus { border: 1px solid #F97316; }
            
            QComboBox {
                background-color: #0F1318;
                border: 1px solid #262B33;
                border-radius: 16px;
                color: #F8FAFC;
                padding: 6px 12px;
            }
            QComboBox:focus { border: 1px solid #F97316; }
            QComboBox::drop-down {
                subcontrol-origin: padding;
                subcontrol-position: top right;
                width: 20px;
                border-left: 1px solid #262B33;
            }
            QComboBox::down-arrow {
                image: none;
                width: 0;
                height: 0;
                border-left: 4px solid transparent;
                border-right: 4px solid transparent;
                border-top: 5px solid #94A3B8;
                margin-right: 6px;
            }
            QComboBox QAbstractItemView {
                background-color: #0F1318;
                border: 1px solid #262B33;
                color: #F8FAFC;
                selection-background-color: #F97316;
                selection-color: #0B0D10;
                border-radius: 16px;
                outline: none;
            }
            
            QTableWidget { background-color: #0F1318; gridline-color: #1F242C; border: 1px solid #1F242C; border-radius: 16px; }
            QTableWidget::item { border-radius: 0px; }
            QHeaderView::section { background-color: #0B0D10; color: #94A3B8; padding: 6px; border: none; font-weight: bold; }
            
            QProgressBar { border: 1px solid #262B33; border-radius: 16px; text-align: center; color: #FFF7ED; font-weight: bold; background-color: #0F1318;}
            QProgressBar::chunk { background-color: #F97316; border-radius: 16px; }
            
            QToolButton { background-color: #141A21; border: 1px solid #262B33; padding: 4px 8px; border-radius: 16px; color: #E2E8F0; }
            QToolButton:hover { background-color: #F97316; color: #0B0D10; font-weight: bold; }
            
            QLabel:disabled, QCheckBox:disabled { color: #475569; }
            QLineEdit:disabled, QComboBox:disabled { background-color: #0B0D10; color: #475569; border: 1px solid #1F242C; }
        """)

    def init_ui(self):
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QHBoxLayout(central_widget)
        main_layout.setContentsMargins(15, 15, 15, 15)
        
        master_splitter = QSplitter(Qt.Horizontal)
        master_splitter.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        main_layout.addWidget(master_splitter)

        # ------------------ LEFT COLUMN: INPUTS & CONTROLS ------------------
        left_container = QFrame()
        left_container.setObjectName("ControlPanel")
        left_layout = QVBoxLayout(left_container)

        # 1. Input Area
        input_group = QGroupBox("Import")
        input_lyt = QVBoxLayout(input_group)
        self.input_area = QTextEdit()
        self.input_area.setPlaceholderText("Paste subscription links, URI nodes, or Clash YAML configs here...")
        self.input_area.textChanged.connect(self.process_imported_text)
        input_lyt.addWidget(self.input_area)

        btn_layout = QHBoxLayout()
        self.import_file_btn = QPushButton("📂 Import File")
        self.import_file_btn.setStyleSheet("QPushButton { background-color: #141A21; border: 1px solid #262B33; color: #E2E8F0; } QPushButton:hover { background-color: #1F242C; }")
        self.import_file_btn.clicked.connect(self.handle_file_import)
        
        self.dedup_btn = QPushButton("🧹 Deduplicate")
        self.dedup_btn.setStyleSheet("QPushButton { background-color: #F97316; border: 1px solid #C2410C; color: #0B0D10; } QPushButton:hover { background-color: #FB923C; border: 1px solid #EA580C; }")
        self.dedup_btn.setToolTip("Removes identical nodes before processing (Detects via UUID/Pass + Server + Port)")
        self.dedup_btn.clicked.connect(self.remove_duplicates)

        self.clear_btn = QPushButton("🗑️ Clear")
        self.clear_btn.setStyleSheet("QPushButton { background-color: #7F1D1D; border: 1px solid #991B1B; } QPushButton:hover { background-color: #991B1B; }")
        self.clear_btn.clicked.connect(self.clear_all_workspaces)
        
        btn_layout.addWidget(self.import_file_btn)
        btn_layout.addWidget(self.dedup_btn)
        btn_layout.addWidget(self.clear_btn)
        input_lyt.addLayout(btn_layout)
        left_layout.addWidget(input_group)

        # 2. Address Overrides (Single + Bulk)
        mod_group = QGroupBox("Address Overrides")
        mod_form = QFormLayout(mod_group)
        self.host_replace_input = QLineEdit()
        self.host_replace_input.setPlaceholderText("Single Force Host (applies to ALL)")
        self.host_replace_input.textChanged.connect(self.trigger_live_update)
        
        self.port_replace_input = QLineEdit()
        self.port_replace_input.setPlaceholderText("Single Force Port (applies to ALL)")
        self.port_replace_input.textChanged.connect(self.trigger_live_update)
        
        self.bulk_hosts_input = QTextEdit()
        self.bulk_hosts_input.setPlaceholderText("Bulk Hosts (comma/newline separated)\nExample:\ncdn1.example.com\ncdn2.example.com")
        self.bulk_hosts_input.setFixedHeight(72)
        self.bulk_hosts_input.textChanged.connect(self.trigger_live_update)
        
        self.bulk_ports_input = QTextEdit()
        self.bulk_ports_input.setPlaceholderText("Bulk Ports (comma/newline separated)\nExample:\n443\n8443")
        self.bulk_ports_input.setFixedHeight(72)
        self.bulk_ports_input.textChanged.connect(self.trigger_live_update)
        
        self.bulk_count_label = QLabel("Bulk Output: 1x")
        self.bulk_count_label.setStyleSheet("color: #FDBA74; font-weight: bold;")
        
        mod_form.addRow("Force Address/Host:", self.host_replace_input)
        mod_form.addRow("Force Port:", self.port_replace_input)
        mod_form.addRow("Bulk Force Hosts:", self.bulk_hosts_input)
        mod_form.addRow("Bulk Force Ports:", self.bulk_ports_input)
        mod_form.addRow("", self.bulk_count_label)
        left_layout.addWidget(mod_group)

        # 3. Geo API Engine Panel
        geo_group = QGroupBox("Geo API")
        geo_layout = QVBoxLayout(geo_group)
        
        self.enable_geo_chk = QCheckBox("Enable Geo Location & Ping Engine (Required for features below)")
        self.enable_geo_chk.setStyleSheet("font-weight: bold; color: #FDBA74;")
        self.enable_geo_chk.toggled.connect(self.toggle_geo_features)
        geo_layout.addWidget(self.enable_geo_chk)
        
        self.geo_sub_panel = QWidget()
        geo_sub_lyt = QGridLayout(self.geo_sub_panel)
        geo_sub_lyt.setContentsMargins(0, 5, 0, 0)
        
        self.provider_combo = QComboBox()
        self.provider_combo.addItems([
            "freeipapi.com", "ip-api.com", "geojs.io", "ipwho.is", 
            "ipapi.co", "api.techniknews.net", "api.ipapi.is"
        ])
        geo_sub_lyt.addWidget(QLabel("Primary Provider:"), 0, 0)
        geo_sub_lyt.addWidget(self.provider_combo, 0, 1)

        self.worker_input = QLineEdit("100")
        self.worker_input.setValidator(QIntValidator(10, 9999))
        self.worker_input.setPlaceholderText("10-9999")
        geo_sub_lyt.addWidget(QLabel("Max Workers:"), 0, 2)
        geo_sub_lyt.addWidget(self.worker_input, 0, 3)

        self.double_check_chk = QCheckBox("Double Check Geo (Consensus Fallback)")
        self.sort_folders_chk = QCheckBox("Export: Sort in folders")
        geo_sub_lyt.addWidget(self.double_check_chk, 1, 0, 1, 2)
        geo_sub_lyt.addWidget(self.sort_folders_chk, 1, 2, 1, 2)
        
        self.connect_through_configs_chk = QCheckBox("Connect through configs (Proxy Geo API to reduce rate-limits)")
        self.connect_through_configs_chk.setToolTip("Requires an external sing-box executable to be installed. If unavailable, falls back to direct requests.")
        geo_sub_lyt.addWidget(self.connect_through_configs_chk, 2, 0, 1, 4)

        self.singbox_path_input = QLineEdit()
        self.singbox_path_input.setPlaceholderText("Path to sing-box executable (e.g. C:\\\\tools\\\\sing-box.exe)")
        self.singbox_browse_btn = QPushButton("Browse")
        self.singbox_browse_btn.setFixedWidth(80)
        self.singbox_browse_btn.clicked.connect(self.browse_singbox_path)
        geo_sub_lyt.addWidget(QLabel("Sing-box Path:"), 3, 0)
        geo_sub_lyt.addWidget(self.singbox_path_input, 3, 1, 1, 2)
        geo_sub_lyt.addWidget(self.singbox_browse_btn, 3, 3)

        self.proxy_node_index_input = QLineEdit("1")
        self.proxy_node_index_input.setValidator(QIntValidator(1, 999999))
        self.proxy_local_port_input = QLineEdit("2080")
        self.proxy_local_port_input.setValidator(QIntValidator(1024, 65535))
        geo_sub_lyt.addWidget(QLabel("Proxy Node #:"), 4, 0)
        geo_sub_lyt.addWidget(self.proxy_node_index_input, 4, 1)
        geo_sub_lyt.addWidget(QLabel("SOCKS Port:"), 4, 2)
        geo_sub_lyt.addWidget(self.proxy_local_port_input, 4, 3)

        geo_sub_lyt.addWidget(QLabel("Locations (comma sep):"), 5, 0)
        self.filter_loc_input = QLineEdit()
        self.filter_loc_input.setPlaceholderText("e.g. US, UK, Germany")
        geo_sub_lyt.addWidget(self.filter_loc_input, 5, 1, 1, 3)
        
        geo_sub_lyt.addWidget(QLabel("Ping Range (ms):"), 6, 0)
        self.filter_ping_input = QLineEdit()
        self.filter_ping_input.setPlaceholderText("e.g. 50-200")
        geo_sub_lyt.addWidget(self.filter_ping_input, 6, 1, 1, 3)
        
        # Line Divider
        line = QFrame()
        line.setFrameShape(QFrame.HLine)
        line.setFrameShadow(QFrame.Sunken)
        line.setStyleSheet("background-color: #2D313E; margin-top: 5px; margin-bottom: 5px;")
        geo_sub_lyt.addWidget(line, 7, 0, 1, 4)

        proto_layout = QHBoxLayout()
        proto_layout.setSpacing(8)
        proto_layout.addWidget(QLabel("Protocols:"))
        self.proto_chks = {}
        for p in ["vmess", "vless", "trojan", "ss", "ssr", "hysteria", "hy2", "hysteria2"]:
            chk = QCheckBox(p.upper())
            chk.setChecked(True)
            self.proto_chks[p] = chk
            proto_layout.addWidget(chk)
        proto_layout.addStretch()
        geo_sub_lyt.addLayout(proto_layout, 8, 0, 1, 4)
        
        geo_layout.addWidget(self.geo_sub_panel)
        self.geo_sub_panel.setEnabled(False) # Disabled by default
        left_layout.addWidget(geo_group)

        # 4. Template & Keyboard
        template_group = QGroupBox("Dynamic Naming")
        template_layout = QVBoxLayout(template_group)

        self.template_input = QLineEdit()
        self.template_input.setText("<flag> | <country> - <city>")
        self.template_input.textChanged.connect(self.trigger_live_update)
        template_layout.addWidget(self.template_input)

        kb_layout = QHBoxLayout()
        kb_layout.setSpacing(6)
        for tag in ["<num:2>", "<country>", "<city>", "<ping>", "<emoji>", "<heart>"]:
            btn = QToolButton()
            btn.setText(tag)
            btn.clicked.connect(lambda checked=False, t=tag: self.insert_into_template(t))
            kb_layout.addWidget(btn)
            
        kb_layout.addStretch()
        template_layout.addLayout(kb_layout)
        
        left_layout.addWidget(template_group)

        # 5. Console
        self.console = LogConsole()
        left_layout.addWidget(self.console, 1)
        master_splitter.addWidget(left_container)

        # ------------------ RIGHT COLUMN: WORKSPACE PREVIEW ------------------
        right_container = QFrame()
        right_container.setObjectName("PreviewPanel")
        right_layout = QVBoxLayout(right_container)

        top_bar = QHBoxLayout()
        self.record_count_label = QLabel("0 Configs")
        self.record_count_label.setStyleSheet("color: #FDBA74; font-weight: bold; font-size: 14px;")
        top_bar.addWidget(QLabel("Preview"))
        top_bar.addStretch()
        top_bar.addWidget(self.record_count_label)
        right_layout.addLayout(top_bar)

        self.preview_table = QTableWidget()
        self.preview_table.setColumnCount(5)
        self.preview_table.setHorizontalHeaderLabels(["Protocol", "Original Name", "Live Preview", "Target Host", "Target Port"])
        self.preview_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        right_layout.addWidget(self.preview_table)

        # Info Panels Container (Telemetry)
        info_container = QFrame()
        info_container.setFixedHeight(210)
        info_layout = QHBoxLayout(info_container)
        info_layout.setContentsMargins(0, 0, 0, 0)
        info_layout.setSpacing(10)
        
        # Style tokens configured with premium margins & zero excess space
        box_style = "QFrame { background-color: #0B0D10; border: 1px solid #1F242C; border-radius: 16px; padding: 2px; } QLabel { color: #94A3B8; font-size: 11px; }"

        # Telemetry Box
        stats_box = QFrame()
        stats_box.setStyleSheet(box_style)
        stats_layout = QVBoxLayout(stats_box)
        stats_layout.setContentsMargins(8, 8, 8, 8)
        stats_layout.setSpacing(1) # Highly compacted spacing
        
        self.lbl_stats_progress = QLabel("Progress: 0 / 0")
        self.lbl_stats_speed = QLabel("Speed: 0 config/s")
        self.lbl_stats_alive_dead = QLabel("Servers: 0 Alive | 0 Dead")
        self.lbl_stats_protocols = QLabel("Protocols: -")
        self.lbl_stats_data = QLabel("Network: 0.00 KB/s | Total: 0.00 KB")
        self.lbl_stats_locations = QLabel("Locations: 0 Known | 0 Unknown")
        self.lbl_stats_api = QLabel("API Usage:\n-")

        title_lbl = QLabel("📊 Live Telemetry & Stats")
        title_lbl.setStyleSheet("color: #F97316; font-size: 12px; font-weight: bold; margin-bottom: 1px;")
        
        stats_layout.addWidget(title_lbl)
        stats_layout.addWidget(self.lbl_stats_progress)
        stats_layout.addWidget(self.lbl_stats_speed)
        stats_layout.addWidget(self.lbl_stats_alive_dead)
        stats_layout.addWidget(self.lbl_stats_protocols)
        stats_layout.addWidget(self.lbl_stats_data)
        stats_layout.addWidget(self.lbl_stats_locations)
        stats_layout.addWidget(self.lbl_stats_api)
        stats_layout.addStretch()
        info_layout.addWidget(stats_box, 1)
        
        right_layout.addWidget(info_container)

        # Bottom Action Bar
        bottom_main_layout = QVBoxLayout()
        
        action_bar = QHBoxLayout()
        
        self.split_input = QLineEdit("0")
        self.split_input.setValidator(QIntValidator(0, 100000))
        self.split_input.setFixedWidth(60)
        self.split_input.setToolTip("Set to 0 for a single file. Set a number to chunk exports.")
        
        action_bar.addWidget(self.split_input)
        action_bar.addWidget(QLabel("Split Output into Parts"))
        action_bar.addStretch()

        self.stop_btn = QPushButton("🛑 STOP")
        self.stop_btn.setMinimumHeight(44)
        self.stop_btn.setStyleSheet("QPushButton { background-color: #DC2626; font-size: 14px; border-radius: 16px; } QPushButton:hover { background-color: #B91C1C; }")
        self.stop_btn.clicked.connect(self.stop_processing)
        self.stop_btn.setEnabled(False)
        action_bar.addWidget(self.stop_btn)

        self.export_btn = QPushButton("🚀 PROCESS")
        self.export_btn.setMinimumHeight(44)
        self.export_btn.setStyleSheet("QPushButton { background-color: #F97316; font-size: 14px; border-radius: 16px; color: #0B0D10; } QPushButton:hover { background-color: #FB923C; }")
        self.export_btn.clicked.connect(self.start_processing)
        action_bar.addWidget(self.export_btn)
        
        bottom_main_layout.addLayout(action_bar)
        
        # Progress Area
        self.progress_bar = QProgressBar()
        self.progress_bar.setValue(0)
        self.progress_bar.setTextVisible(True)
        self.progress_bar.setFormat("Ready")
        bottom_main_layout.addWidget(self.progress_bar)
        
        self.eta_label = QLabel("")
        self.eta_label.setStyleSheet("color: #F8FAFC;")
        self.eta_label.setAlignment(Qt.AlignCenter)
        bottom_main_layout.addWidget(self.eta_label)

        right_layout.addLayout(bottom_main_layout)
        
        master_splitter.addWidget(right_container)
        master_splitter.setSizes([580, 700])

    def toggle_geo_features(self, state):
        self.geo_sub_panel.setEnabled(state)

    def insert_into_template(self, tag: str):
        pos = self.template_input.cursorPosition()
        current_text = self.template_input.text()
        self.template_input.setText(current_text[:pos] + tag + current_text[pos:])
        self.template_input.setFocus()
        self.template_input.setCursorPosition(pos + len(tag))

    def clear_all_workspaces(self):
        self.input_area.blockSignals(True)
        self.input_area.clear()
        self.input_area.blockSignals(False)
        self.loaded_configs = []
        self.clash_headers = {}
        self.preview_table.setRowCount(0)
        self.record_count_label.setText("0 Configs Detected")
        
        self.progress_bar.setValue(0)
        self.progress_bar.setFormat("Ready")
        self.eta_label.setText("")
        
        # Reset Telemetry Labels
        self.lbl_stats_progress.setText("Progress: 0 / 0")
        self.lbl_stats_speed.setText("Speed: 0 config/s")
        self.lbl_stats_alive_dead.setText("Servers: 0 Alive | 0 Dead")
        self.lbl_stats_protocols.setText("Protocols: -")
        self.lbl_stats_data.setText("Network: 0.00 KB/s | Total: 0.00 KB")
        self.lbl_stats_locations.setText("Locations: 0 Known | 0 Unknown")
        self.lbl_stats_api.setText("API Usage:\n-")

    def handle_file_import(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Open Subscription", "", "All Support Configs (*.txt *.yaml *.yml *.json);;Clash (*.yaml)")
        if not file_path: return
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                self.input_area.setPlainText(f.read())
            self.console.log(f"Successfully loaded: {file_path}", "SUCCESS")
        except Exception as e:
            QMessageBox.critical(self, "Import Error", f"Failed to read:\n{str(e)}")

    def browse_singbox_path(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Select sing-box executable", "", "Executable (*.exe);;All Files (*)")
        if file_path:
            self.singbox_path_input.setText(file_path)

    @Slot()
    def remove_duplicates(self):
        if not self.loaded_configs:
            QMessageBox.information(self, "No configs", "Please import configurations first.")
            return
            
        seen = set()
        unique_configs = []
        removed_count = 0
        
        for config in self.loaded_configs:
            # We construct a signature matching the specific auth id (UUID/pass), the host, and port
            sig = (config.auth_id, config.current_host, config.current_port)
            if sig in seen:
                removed_count += 1
            else:
                seen.add(sig)
                unique_configs.append(config)
                
        if removed_count > 0:
            self.loaded_configs = unique_configs
            self.trigger_live_update()
            self.console.log(f"Cleaned up {removed_count} duplicate configurations.", "SUCCESS")
        else:
            self.console.log("No duplicates found. All configs seem strictly unique.", "INFO")

    @Slot()
    def process_imported_text(self):
        raw_text = self.input_area.toPlainText().strip()
        self.loaded_configs.clear()
        self.clash_headers.clear()
        if not raw_text:
            self.preview_table.setRowCount(0)
            self.record_count_label.setText("0 Configs Detected")
            return

        is_yaml, parsed_yaml = False, None
        if "proxies:" in raw_text:
            try:
                parsed_yaml = yaml.safe_load(raw_text)
                if isinstance(parsed_yaml, dict) and "proxies" in parsed_yaml: is_yaml = True
            except Exception: pass

        if is_yaml:
            for k, v in parsed_yaml.items():
                if k != "proxies": self.clash_headers[k] = v
            for i, item in enumerate(parsed_yaml.get("proxies", []), 1):
                if isinstance(item, dict):
                    self.loaded_configs.append(ConfigItem(item, i, "CLASH_DICT"))
        else:
            idx = 1
            for line in raw_text.splitlines():
                line = line.strip()
                if line and not line.startswith("#") and not line.startswith("//"):
                    self.loaded_configs.append(ConfigItem(line, idx, "URI"))
                    idx += 1
        self.trigger_live_update()

    def parse_bulk_entries(self, raw_text: str):
        if not raw_text:
            return []
        parts = []
        for token in re.split(r"[,\r\n\t ]+", raw_text.strip()):
            t = token.strip()
            if t:
                parts.append(t)
        return parts

    def build_variants(self):
        g_host = self.host_replace_input.text().strip()
        g_port = self.port_replace_input.text().strip()
        hosts = self.parse_bulk_entries(self.bulk_hosts_input.toPlainText())
        ports = self.parse_bulk_entries(self.bulk_ports_input.toPlainText())
        host_pool = hosts if hosts else [""]
        port_pool = ports if ports else [""]

        variants = []
        for config in self.loaded_configs:
            for h in host_pool:
                for p in port_pool:
                    force_h = h if h else g_host
                    force_p = p if p else g_port
                    variants.append(ConfigVariant(config, force_h, force_p))

        return variants, len(host_pool) * len(port_pool)

    @Slot()
    def trigger_live_update(self):
        template = self.template_input.text()
        variants, bulk_mult = self.build_variants() if self.loaded_configs else ([], 1)
        self.bulk_count_label.setText(f"Bulk Output: {bulk_mult}x")
        if self.loaded_configs:
            self.record_count_label.setText(f"{len(self.loaded_configs)} Configs → {len(variants)} Outputs")
        else:
            self.record_count_label.setText("0 Configs")

        # Generate Protocol Telemetry counts globally
        proto_counts = Counter(c.protocol.lower() for c in variants)
        proto_str = ", ".join(f"{k.upper()}: {v}" for k, v in proto_counts.items())
        if not proto_str: proto_str = "None"
        self.lbl_stats_protocols.setText(f"Protocols: {proto_str}")

        self.preview_table.setRowCount(0)
        self.preview_table.setRowCount(len(variants))
        
        emoji_font = QFont()
        emoji_font.setFamilies(["Calibri", "Segoe UI Emoji", "Apple Color Emoji", "Noto Color Emoji", "sans-serif"])
        emoji_font.setPointSize(11)

        for idx, config in enumerate(variants):
            name_instance = template
            
            # Placeholders for live preview (to be filled during Geo extraction phase)
            name_instance = name_instance.replace("<protocol>", config.protocol.upper())
            name_instance = name_instance.replace("<country>", "[Geo]")
            name_instance = name_instance.replace("<city>", "[Geo]")
            name_instance = name_instance.replace("<asn>", "[ASN]")
            name_instance = name_instance.replace("<flag>", "🏳️")
            name_instance = name_instance.replace("<ping>", "[Ping]")
            
            # Pad numbers statically
            for tag_spec in re.findall(r"<num(?::(\d+))?>", name_instance):
                t_str = "<num>" if not tag_spec else f"<num:{tag_spec}>"
                name_instance = name_instance.replace(t_str, str(idx + 1).zfill(int(tag_spec) if tag_spec else 1))

            # Fix emoji rendering in preview table 
            while "<emoji>" in name_instance: name_instance = name_instance.replace("<emoji>", random.choice(EMOJIS), 1)
            while "<heart>" in name_instance: name_instance = name_instance.replace("<heart>", random.choice(HEARTS), 1)

            disp_host = getattr(config, "effective_host", config.current_host)
            disp_port = getattr(config, "effective_port", config.current_port)

            item_proto = QTableWidgetItem(config.protocol.upper())
            item_proto.setTextAlignment(Qt.AlignCenter)
            
            item_orig = QTableWidgetItem(config.original_name)
            item_orig.setFont(emoji_font)
            
            item_trans = QTableWidgetItem(name_instance)
            item_trans.setForeground(QColor("#10B981"))
            item_trans.setFont(emoji_font)
            
            item_h = QTableWidgetItem(disp_host)
            item_p = QTableWidgetItem(disp_port)
            if getattr(config, "force_host", ""): item_h.setForeground(QColor("#FDBA74"))
            if getattr(config, "force_port", ""): item_p.setForeground(QColor("#FDBA74"))

            self.preview_table.setItem(idx, 0, item_proto)
            self.preview_table.setItem(idx, 1, item_orig)
            self.preview_table.setItem(idx, 2, item_trans)
            self.preview_table.setItem(idx, 3, item_h)
            self.preview_table.setItem(idx, 4, item_p)

    def start_processing(self):
        if not self.loaded_configs:
            QMessageBox.warning(self, "Warning", "No configs loaded to process.")
            return

        variants, _ = self.build_variants()

        is_yaml = any(c.config_type == "CLASH_DICT" for c in self.loaded_configs)
        file_path, _ = QFileDialog.getSaveFileName(self, "Save Export File", "exported_nodes.yaml" if is_yaml else "exported_nodes.txt", "YAML Config (*.yaml *.yml);;Text File (*.txt)")
        
        if not file_path: return
        self.target_export_path = file_path
        self.is_yaml_export = is_yaml

        params = {
            "template": self.template_input.text(),
            "force_host": "",
            "force_port": "",
            "geo_enabled": self.enable_geo_chk.isChecked(),
            "provider": self.provider_combo.currentText(),
            "max_workers": self.worker_input.text() or "100",
            "double_check": self.double_check_chk.isChecked(),
            "sort_folders": self.sort_folders_chk.isChecked(),
            "loc_filter": self.filter_loc_input.text(),
            "ping_filter": self.filter_ping_input.text(),
            "enabled_protos": [p for p, chk in self.proto_chks.items() if chk.isChecked()],
            "geo_proxy_enabled": self.connect_through_configs_chk.isChecked(),
            "singbox_path": self.singbox_path_input.text().strip(),
            "proxy_node_index": self.proxy_node_index_input.text().strip(),
            "proxy_socks_port": self.proxy_local_port_input.text().strip(),
            "proxy_base_config": None
        }

        if "hy2" in params["enabled_protos"] and "hysteria2" not in params["enabled_protos"]:
            params["enabled_protos"].append("hysteria2")
        if "hysteria2" in params["enabled_protos"] and "hy2" not in params["enabled_protos"]:
            params["enabled_protos"].append("hy2")

        try:
            idx = int(params["proxy_node_index"]) - 1
            if 0 <= idx < len(self.loaded_configs):
                params["proxy_base_config"] = self.loaded_configs[idx]
        except ValueError:
            pass

        if not params["geo_enabled"]:
            template = params["template"]
            out = {"Default": []}
            for idx, config in enumerate(variants):
                name_instance = template
                name_instance = name_instance.replace("<protocol>", config.protocol.upper())
                name_instance = name_instance.replace("<country>", "-")
                name_instance = name_instance.replace("<city>", "-")
                name_instance = name_instance.replace("<asn>", "-")
                name_instance = name_instance.replace("<flag>", "🏳️")
                name_instance = name_instance.replace("<ping>", "-")
                
                for tag_spec in re.findall(r"<num(?::(\d+))?>", name_instance):
                    t_str = "<num>" if not tag_spec else f"<num:{tag_spec}>"
                    name_instance = name_instance.replace(t_str, str(idx + 1).zfill(int(tag_spec) if tag_spec else 1))

                while "<emoji>" in name_instance: name_instance = name_instance.replace("<emoji>", random.choice(EMOJIS), 1)
                while "<heart>" in name_instance: name_instance = name_instance.replace("<heart>", random.choice(HEARTS), 1)
                
                out["Default"].append(config.get_updated_data(name_instance, "", ""))

            self.export_btn.setEnabled(True)
            self.stop_btn.setEnabled(False)
            self.progress_bar.setMaximum(len(variants) if variants else 1)
            self.progress_bar.setValue(len(variants))
            self.progress_bar.setFormat("Done")
            self.eta_label.setText("")
            self.finalize_export(out)
            return

        self.export_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self.progress_bar.setValue(0)
        self.progress_bar.setFormat("%v / %m (0%)")
        self.eta_label.setText("Initializing...")
        self.console.log(f"Engaging worker thread (Max Workers: {params['max_workers']}). Please wait...", "INFO")

        self.worker = ProcessWorker(variants, params)
        self.worker.progress_update.connect(self.update_progress)
        self.worker.log_msg.connect(self.console.log)
        self.worker.finished_data.connect(self.finalize_export)
        self.worker.start()

    def stop_processing(self):
        if self.worker and self.worker.isRunning():
            self.console.log("Stop sequence initiated. Finishing active tasks...", "WARN")
            self.eta_label.setText("Stopping... Gathering processed configs.")
            self.stop_btn.setEnabled(False)
            self.worker.stop()

    @Slot(dict)
    def update_progress(self, stat_dict):
        self.progress_bar.setMaximum(stat_dict["total"])
        self.progress_bar.setValue(stat_dict["current"])
        self.progress_bar.setFormat(f"%v / %m ({stat_dict['pct_str']})")
        self.eta_label.setText(stat_dict["eta_str"])
        
        # Telemetry Labels Update
        self.lbl_stats_progress.setText(f"Progress: {stat_dict['current']} / {stat_dict['total']}")
        self.lbl_stats_speed.setText(f"Speed: {stat_dict['speed']:.1f} config/s")
        self.lbl_stats_alive_dead.setText(f"Servers: {stat_dict['alive']} Alive | {stat_dict['dead']} Dead")
        
        kb_used = stat_dict["bytes_used"] / 1024
        kb_sec = stat_dict["bytes_sec"] / 1024
        self.lbl_stats_data.setText(f"Network: {kb_sec:.2f} KB/s | Total: {kb_used:.2f} KB")
        self.lbl_stats_locations.setText(f"Locations: {stat_dict['known_loc']} Known | {stat_dict['unknown_loc']} Unknown")
        
        # Format API usage into clean rows of max 3 APIs to prevent layout stretching
        api_names = {
            "freeipapi.com": "FreeIP", "ip-api.com": "IP-API", "geojs.io": "GeoJS", 
            "ipwho.is": "IPWho", "ipapi.co": "IPApiCo", "api.techniknews.net": "Technik", 
            "api.ipapi.is": "IPApiIs"
        }
        active_apis = [f"{api_names.get(k, k)}: {v}" for k, v in stat_dict["api_usage"].items() if v > 0]
        
        if active_apis:
            rows = []
            for i in range(0, len(active_apis), 3):
                rows.append(" | ".join(active_apis[i:i+3]))
            api_str = "\n".join(rows)
        else:
            api_str = "-"
            
        self.lbl_stats_api.setText(f"API Usage:\n{api_str}")

    @Slot(dict)
    def finalize_export(self, results_dict):
        self.export_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.eta_label.setText("Process Concluded.")
        
        if not results_dict:
            self.console.log("Process yielded 0 nodes (filtered out or empty).", "WARN")
            QMessageBox.warning(self, "Export", "No configurations matched the filter criteria or process was cancelled early.")
            return
            
        try: chunk_size = int(self.split_input.text())
        except ValueError: chunk_size = 0

        base_dir = os.path.dirname(self.target_export_path)
        base_name, ext = os.path.splitext(os.path.basename(self.target_export_path))
        
        total_saved = 0
        merged_count = 0
        
        for folder_name, payload_list in results_dict.items():
            if not payload_list: continue
            
            target_dir = base_dir
            if folder_name != "Default":
                target_dir = os.path.join(base_dir, folder_name)
                os.makedirs(target_dir, exist_ok=True)
                
            chunks = [payload_list[i:i + chunk_size] for i in range(0, len(payload_list), chunk_size)] if chunk_size > 0 else [payload_list]
            
            for idx, chunk in enumerate(chunks, 1):
                f_name = f"{base_name}_part{idx}{ext}" if len(chunks) > 1 else f"{base_name}{ext}"
                out_path = os.path.join(target_dir, f_name)
                
                if self.is_yaml_export:
                    existing_proxies = []
                    final_yaml = {}
                    
                    # Merge with existing Clash configuration file
                    if os.path.exists(out_path):
                        try:
                            with open(out_path, "r", encoding="utf-8", errors="ignore") as f:
                                existing_yaml = yaml.safe_load(f)
                            if isinstance(existing_yaml, dict):
                                final_yaml = existing_yaml
                                existing_proxies = existing_yaml.get("proxies", [])
                                if not isinstance(existing_proxies, list):
                                    existing_proxies = []
                        except Exception as e:
                            self.console.log(f"Failed parsing existing YAML {f_name} for merging: {str(e)}", "WARN")
                    
                    if not final_yaml:
                        final_yaml = self.clash_headers.copy()
                        
                    # Deduplicate Clash proxies (based on unique config: Name, Server, Port, UUID/Password)
                    seen_sigs = set()
                    merged_proxies = []
                    
                    for p in existing_proxies + chunk:
                        if not isinstance(p, dict):
                            continue
                        sig = (
                            str(p.get("name", "")).strip(),
                            str(p.get("server", "")).strip(),
                            str(p.get("port", "")).strip(),
                            str(p.get("uuid", p.get("password", ""))).strip()
                        )
                        if sig not in seen_sigs:
                            seen_sigs.add(sig)
                            merged_proxies.append(p)
                            
                    merged_count += len(merged_proxies) - len(chunk)
                    final_yaml["proxies"] = merged_proxies
                    
                    try:
                        with open(out_path, "w", encoding="utf-8") as f:
                            yaml.dump(final_yaml, f, default_flow_style=False, allow_unicode=True, sort_keys=False)
                        total_saved += len(chunk)
                    except Exception as e:
                        self.console.log(f"Error saving YAML to {out_path}: {str(e)}", "ERROR")
                else:
                    # Merge with existing text file containing URIs
                    existing_lines = []
                    if os.path.exists(out_path):
                        try:
                            with open(out_path, "r", encoding="utf-8", errors="ignore") as f:
                                for line in f:
                                    line_str = line.strip()
                                    if line_str and not line_str.startswith("#") and not line_str.startswith("//"):
                                        existing_lines.append(line_str)
                        except Exception as e:
                            self.console.log(f"Could not read existing file {f_name} for merging: {str(e)}", "WARN")
                            
                    # Combine & deduplicate URIs
                    seen_uris = set()
                    merged_uris = []
                    for line in existing_lines + chunk:
                        line_str = str(line).strip()
                        if line_str and line_str not in seen_uris:
                            seen_uris.add(line_str)
                            merged_uris.append(line_str)
                            
                    merged_count += len(merged_uris) - len(chunk)
                    
                    try:
                        with open(out_path, "w", encoding="utf-8") as f:
                            for line in merged_uris:
                                f.write(str(line) + "\n")
                        total_saved += len(chunk)
                    except Exception as e:
                        self.console.log(f"Error saving to {out_path}: {str(e)}", "ERROR")
                
        if merged_count > 0:
            self.console.log(f"Export Success! {total_saved} configurations written to disk (merged with {merged_count} existing unique configurations).", "SUCCESS")
            QMessageBox.information(self, "Export Complete", f"Successfully exported {total_saved} processed nodes (Merged & deduplicated with existing ones).")
        else:
            self.console.log(f"Export Success! {total_saved} configurations written to disk.", "SUCCESS")
            QMessageBox.information(self, "Export Complete", f"Successfully exported {total_saved} processed nodes.")


if __name__ == "__main__":
    app = QApplication(sys.argv)
    dark_palette = QPalette()
    dark_palette.setColor(QPalette.Window, QColor("#12141A"))
    dark_palette.setColor(QPalette.WindowText, QColor("#E2E8F0"))
    dark_palette.setColor(QPalette.Base, QColor("#1E222B"))
    dark_palette.setColor(QPalette.AlternateBase, QColor("#161920"))
    dark_palette.setColor(QPalette.ToolTipBase, QColor("#12141A"))
    dark_palette.setColor(QPalette.ToolTipText, QColor("#F8FAFC"))
    dark_palette.setColor(QPalette.Text, QColor("#F8FAFC"))
    dark_palette.setColor(QPalette.Button, QColor("#1A1D24"))
    dark_palette.setColor(QPalette.ButtonText, QColor("#E2E8F0"))
    app.setPalette(dark_palette)

    window = App()
    window.show()
    sys.exit(app.exec())
