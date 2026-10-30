"""
Meikova Platform - Universal Tunnel Manager (Python Edition)
Integrates Cloudflare Quick Tunnel (trycloudflare.com) for One-Click WAN exposure
Zero-config, NAT/Firewall traversal, HTTPS encryption, Edge PoP & Latency Detection
"""

import atexit
import os
import re
import shutil
import socket
import subprocess
import sys
import threading
import time
import urllib.request
from typing import Any, Callable, Dict, Optional

# Cloudflare Edge Colocation (IATA Airport Codes) SSOT Map
COLO_LOCATIONS = {
    "HAN": "Hà Nội (Việt Nam)", "SGN": "TP. Hồ Chí Minh (Việt Nam)",
    "HKG": "Hong Kong", "SIN": "Singapore", "BKK": "Bangkok (Thái Lan)",
    "KUL": "Kuala Lumpur (Malaysia)", "TPE": "Đài Bắc (Taiwan)",
    "NRT": "Tokyo Narita (Nhật Bản)", "HND": "Tokyo Haneda (Nhật Bản)",
    "KIX": "Osaka (Nhật Bản)", "ICN": "Seoul (Hàn Quốc)",
    "MNL": "Manila (Philippines)", "CGK": "Jakarta (Indonesia)",
    "SYD": "Sydney (Úc)", "MEL": "Melbourne (Úc)", "LAX": "Los Angeles (Mỹ)",
    "SFO": "San Francisco (Mỹ)", "SJC": "San Jose (Mỹ)", "SEA": "Seattle (Mỹ)",
    "ORD": "Chicago (Mỹ)", "IAD": "Washington DC (Mỹ)", "EWR": "Newark / New York (Mỹ)",
    "JFK": "New York (Mỹ)", "LHR": "London (Anh)", "FRA": "Frankfurt (Đức)",
    "AMS": "Amsterdam (Hà Lan)", "CDG": "Paris (Pháp)"
}


class CloudflaredTunnelManager:
    def __init__(self):
        self.process: Optional[subprocess.Popen] = None
        self.tunnel_url: Optional[str] = None
        self.status: str = "idle"  # 'idle' | 'starting' | 'running' | 'failed'
        self.error: Optional[str] = None
        self.started_at: Optional[int] = None
        self.active_port: int = 8990
        self.edge_ip_version: str = "auto"  # 'auto' | '4' | '6'
        self.edge_colo: Optional[str] = None
        self.edge_location: Optional[str] = None
        self.latency_ms: Optional[int] = None
        self._lock = threading.Lock()
        self.on_state_change: Optional[Callable[[Dict[str, Any]], None]] = None

    def find_cloudflared(self) -> Optional[str]:
        # 1. Check PATH
        path_bin = shutil.which("cloudflared")
        if path_bin and os.path.isfile(path_bin):
            return path_bin

        # 2. Standard filesystem paths
        candidates = []
        if sys.platform == "win32":
            prog_x86 = os.environ.get("ProgramFiles(x86)")
            prog_files = os.environ.get("ProgramFiles")
            local_appdata = os.environ.get("LOCALAPPDATA")

            if prog_x86:
                candidates.append(os.path.join(prog_x86, "cloudflared", "cloudflared.exe"))
            if prog_files:
                candidates.append(os.path.join(prog_files, "cloudflared", "cloudflared.exe"))
            if local_appdata:
                candidates.append(os.path.join(local_appdata, "Programs", "cloudflared", "cloudflared.exe"))
                candidates.append(os.path.join(local_appdata, "Microsoft", "WinGet", "Packages", "cloudflared.exe"))
        else:
            candidates.extend([
                "/usr/local/bin/cloudflared",
                "/usr/bin/cloudflared",
                "/opt/homebrew/bin/cloudflared"
            ])

        for cand in candidates:
            if cand and os.path.isfile(cand):
                return cand

        return None

    def get_install_command(self) -> str:
        if sys.platform == "win32":
            return "winget install --id Cloudflare.cloudflared --exact --silent"
        elif sys.platform == "darwin":
            return "brew install cloudflared"
        else:
            return "curl -L --output cloudflared.deb https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64.deb && sudo dpkg -i cloudflared.deb"

    def get_status(self) -> Dict[str, Any]:
        bin_path = self.find_cloudflared()
        return {
            "running": self.status == "running",
            "status": self.status,
            "url": self.tunnel_url,
            "error": self.error,
            "startedAt": self.started_at,
            "port": self.active_port,
            "installed": bool(bin_path),
            "binaryPath": bin_path,
            "platform": sys.platform,
            "installCommand": self.get_install_command(),
            "edgeIpVersion": self.edge_ip_version,
            "edgeColo": self.edge_colo,
            "edgeLocation": self.edge_location,
            "latencyMs": self.latency_ms,
        }

    def start(self, port: int = 8990, ip_version: str = "auto", timeout_secs: int = 35) -> Dict[str, Any]:
        with self._lock:
            if self.status == "running" and self.tunnel_url:
                return self.get_status()

            bin_path = self.find_cloudflared()
            if not bin_path:
                self.status = "failed"
                self.error = "CLOUDFLARED_NOT_INSTALLED"
                raise RuntimeError(self.error)

            self.active_port = port
            self.edge_ip_version = ip_version or "auto"
            self.edge_colo = None
            self.edge_location = None
            self.latency_ms = None
            self.status = "starting"
            self.error = None
            self._notify_state()

            try:
                creationflags = 0
                if sys.platform == "win32":
                    creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000)

                self.process = subprocess.Popen(
                    [
                        bin_path,
                        "tunnel",
                        "--protocol",
                        "http2",
                        "--edge-ip-version",
                        self.edge_ip_version,
                        "--no-autoupdate",
                        "--url",
                        f"http://127.0.0.1:{port}",
                    ],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    bufsize=1,
                    creationflags=creationflags,
                )
            except Exception as e:
                self.status = "failed"
                self.error = str(e)
                self._notify_state()
                raise

            url_found_event = threading.Event()

            def _reader_thread():
                url_regex = re.compile(r"https://[a-zA-Z0-9-]+\.trycloudflare\.com")
                colo_regex = re.compile(r"location=([a-zA-Z]{3})[0-9]*", re.IGNORECASE)
                if self.process and self.process.stderr:
                    for line in self.process.stderr:
                        if not line:
                            break
                        # Detect Edge PoP Colocation (e.g., location=hkg09, location=sin02)
                        loc_match = colo_regex.search(line)
                        if loc_match and not self.edge_colo:
                            code = loc_match.group(1).upper()
                            self.edge_colo = code
                            self.edge_location = COLO_LOCATIONS.get(code, code)
                            if self.status == "running":
                                self._notify_state()

                        match = url_regex.search(line)
                        if match and not self.tunnel_url:
                            self.tunnel_url = match.group(0)
                            self.status = "running"
                            self.started_at = int(time.time() * 1000)
                            self._notify_state()
                            url_found_event.set()

            t = threading.Thread(target=_reader_thread, daemon=True)
            t.start()

        if url_found_event.wait(timeout=timeout_secs):
            self._measure_latency()
            return self.get_status()

        with self._lock:
            if self.status != "running":
                self.stop()
                self.status = "failed"
                self.error = "TUNNEL_CONNECTION_TIMEOUT"
                self._notify_state()
                raise TimeoutError(self.error)
            self._measure_latency()
            return self.get_status()

    def _measure_latency(self):
        if self.status != "running":
            return

        # 1. Pure 1-RTT TCP Handshake Latency directly to Cloudflare Anycast IP (1.1.1.1:443)
        t0 = time.time()
        try:
            s = socket.create_connection(("1.1.1.1", 443), timeout=1.2)
            self.latency_ms = int((time.time() - t0) * 1000)
            s.close()
        except Exception:
            pass

        # 2. Fetch Colo identity from Cloudflare trace if not captured from stderr
        if not self.edge_colo:
            try:
                req = urllib.request.Request(
                    "https://1.1.1.1/cdn-cgi/trace",
                    headers={"User-Agent": "Meikova-ColoCheck"},
                )
                with urllib.request.urlopen(req, timeout=1.5) as resp:
                    body = resp.read().decode("utf-8", errors="ignore")
                    m = re.search(r"^colo=([A-Za-z]{3})", body, re.MULTILINE)
                    if m:
                        code = m.group(1).upper()
                        self.edge_colo = code
                        self.edge_location = COLO_LOCATIONS.get(code, code)
            except Exception:
                pass

        self._notify_state()

    def stop(self) -> Dict[str, Any]:
        with self._lock:
            if self.process:
                try:
                    if sys.platform == "win32" and self.process.pid:
                        subprocess.run(
                            ["taskkill", "/pid", str(self.process.pid), "/t", "/f"],
                            stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL,
                            check=False,
                        )
                    else:
                        self.process.terminate()
                        self.process.wait(timeout=2)
                except Exception:
                    try:
                        self.process.kill()
                    except Exception:
                        pass
                self.process = None

            self.status = "idle"
            self.tunnel_url = None
            self.started_at = None
            self.edge_colo = None
            self.edge_location = None
            self.latency_ms = None
            self._notify_state()
            return self.get_status()

    def toggle(self, port: int = 8990, ip_version: str = "auto") -> Dict[str, Any]:
        if self.status == "running":
            return self.stop()
        else:
            return self.start(port, ip_version=ip_version)

    def _notify_state(self):
        if callable(self.on_state_change):
            try:
                self.on_state_change(self.get_status())
            except Exception:
                pass


tunnel_manager = CloudflaredTunnelManager()
atexit.register(tunnel_manager.stop)
