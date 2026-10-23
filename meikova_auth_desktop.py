# -*- coding: utf-8 -*-
"""
Meikova Auth Desktop Application Launcher
Multiplatform Desktop Shell using Microsoft Edge WebView2 (pywebview)
Features:
- Frameless custom titlebar integration (Zero-OS-Chrome)
- Windows High-DPI Awareness (Per-Monitor v2)
- Zero-Profile-Pollution: local app data in %LOCALAPPDATA%/MeikovaAuth
- System Tray support with Brand Squircle (#11151B + #A6C5FF)
- Background Uvicorn FastAPI Server auto-lifecycle
"""

import os
import sys
import time
import socket
import logging
import argparse
import threading
from pathlib import Path

# Zero-Profile-Pollution Data Directory
if sys.platform == "win32":
    LOCAL_APP_DATA = Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData" / "Local")) / "MeikovaAuth"
else:
    LOCAL_APP_DATA = Path.home() / ".meikova-auth"

LOCAL_APP_DATA.mkdir(parents=True, exist_ok=True)
os.environ["MEIKOVA_AUTH_DATA_DIR"] = str(LOCAL_APP_DATA)

# Configure logging
LOG_FILE = LOCAL_APP_DATA / "desktop.log"
logging.basicConfig(
    filename=str(LOG_FILE),
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("meikova.auth.desktop")

AUTH_ROOT = Path(__file__).resolve().parent
if str(AUTH_ROOT) not in sys.path:
    sys.path.insert(0, str(AUTH_ROOT))

# Windows DPI Awareness
if sys.platform == "win32":
    try:
        import ctypes
        ctypes.windll.user32.SetProcessDpiAwarenessContext(ctypes.c_void_p(-4))
    except Exception:
        try:
            import ctypes
            ctypes.windll.shcore.SetProcessDpiAwareness(2)
        except Exception:
            pass


def find_free_port(start_port: int = 8990) -> int:
    port = start_port
    while port < 9999:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            if s.connect_ex(("127.0.0.1", port)) != 0:
                return port
        port += 1
    return start_port


class DesktopApi:
    """JS-to-Python Bridge for Frameless Window Titlebar Controls."""
    def __init__(self, window=None):
        self._window = window

    def set_window(self, window):
        self._window = window

    def minimize(self):
        if self._window:
            self._window.minimize()

    def toggle_maximize(self):
        if self._window:
            if getattr(self._window, 'maximized', False):
                self._window.restore()
                self._window.maximized = False
            else:
                self._window.maximize()
                self._window.maximized = True

    def close(self):
        if self._window:
            self._window.destroy()


def run_server(port: int):
    import uvicorn
    from server import app
    os.environ["PORT"] = str(port)
    config = uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning")
    server = uvicorn.Server(config)
    server.run()


def main():
    parser = argparse.ArgumentParser(description="Meikova Auth Desktop Launcher")
    parser.add_argument("--port", type=int, default=0, help="Local port for internal server")
    parser.add_argument("--browser-only", action="store_true", help="Launch in default web browser instead of WebView2")
    args = parser.parse_args()

    port = args.port or find_free_port(8990)
    server_url = f"http://127.0.0.1:{port}"

    # Start FastAPI server in daemon thread
    server_thread = threading.Thread(target=run_server, args=(port,), daemon=True)
    server_thread.start()

    # Wait for server readiness
    ready = False
    for _ in range(50):
        time.sleep(0.1)
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            if s.connect_ex(("127.0.0.1", port)) == 0:
                ready = True
                break

    if not ready:
        logger.error(f"Server failed to start on {server_url}")
        sys.exit(1)

    logger.info(f"Meikova Auth Server running on {server_url}")

    # Launch PyWebView Frameless Window
    try:
        if args.browser_only:
            raise ImportError("Browser-only mode requested")

        import webview
        api = DesktopApi()
        window = webview.create_window(
            title="Meikova Auth",
            url=f"{server_url}/dashboard?platform=desktop",
            width=1180,
            height=820,
            min_size=(800, 600),
            frameless=True,
            easy_drag=False,
            background_color="#070D17",
            js_api=api
        )
        api.set_window(window)
        webview.start(gui="edgechromium", debug=False)

    except Exception as e:
        logger.info(f"PyWebView not available ({e}), opening default system browser.")
        import webbrowser
        webbrowser.open(f"{server_url}/dashboard")
        print(f"\n=======================================================")
        print(f"  Meikova Auth Gateway & Credential Manager")
        print(f"  Dang chay tren: {server_url}")
        print(f"  Nhan Ctrl+C de dung ung dung")
        print(f"=======================================================\n")
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print("\nDa dung Meikova Auth.")


if __name__ == "__main__":
    main()
