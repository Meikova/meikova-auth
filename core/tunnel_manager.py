"""
Meikova Platform - Universal Tunnel Manager (Python Edition)
Integrates Cloudflare Quick Tunnel (trycloudflare.com) for One-Click WAN exposure
Zero-config, NAT/Firewall traversal, HTTPS encryption
"""

import atexit
import os
import re
import shutil
import subprocess
import sys
import threading
import time
from typing import Any, Callable, Dict, Optional


class CloudflaredTunnelManager:
    def __init__(self):
        self.process: Optional[subprocess.Popen] = None
        self.tunnel_url: Optional[str] = None
        self.status: str = "idle"  # 'idle' | 'starting' | 'running' | 'failed'
        self.error: Optional[str] = None
        self.started_at: Optional[int] = None
        self.active_port: int = 8990
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
        }

    def start(self, port: int = 8990, timeout_secs: int = 35) -> Dict[str, Any]:
        with self._lock:
            if self.status == "running" and self.tunnel_url:
                return self.get_status()

            bin_path = self.find_cloudflared()
            if not bin_path:
                self.status = "failed"
                self.error = "CLOUDFLARED_NOT_INSTALLED"
                raise RuntimeError(self.error)

            self.active_port = port
            self.status = "starting"
            self.error = None
            self._notify_state()

            try:
                creationflags = 0
                if sys.platform == "win32":
                    creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000)

                self.process = subprocess.Popen(
                    [bin_path, "tunnel", "--protocol", "http2", "--edge-ip-version", "auto", "--no-autoupdate", "--url", f"http://127.0.0.1:{port}"],
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
                regex = re.compile(r"https://[a-zA-Z0-9-]+\.trycloudflare\.com")
                if self.process and self.process.stderr:
                    for line in self.process.stderr:
                        if not line:
                            break
                        match = regex.search(line)
                        if match and not self.tunnel_url:
                            self.tunnel_url = match.group(0)
                            self.status = "running"
                            self.started_at = int(time.time() * 1000)
                            self._notify_state()
                            url_found_event.set()

            t = threading.Thread(target=_reader_thread, daemon=True)
            t.start()

        if url_found_event.wait(timeout=timeout_secs):
            return self.get_status()

        with self._lock:
            if self.status != "running":
                self.stop()
                self.status = "failed"
                self.error = "TUNNEL_CONNECTION_TIMEOUT"
                self._notify_state()
                raise TimeoutError(self.error)
            return self.get_status()

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
            self._notify_state()
            return self.get_status()

    def toggle(self, port: int = 8990) -> Dict[str, Any]:
        if self.status == "running":
            return self.stop()
        else:
            return self.start(port)

    def _notify_state(self):
        if callable(self.on_state_change):
            try:
                self.on_state_change(self.get_status())
            except Exception:
                pass


tunnel_manager = CloudflaredTunnelManager()
atexit.register(tunnel_manager.stop)
