# -*- coding: utf-8 -*-
"""
Meikova Auth - Cloudflared Tunnel Manager Test Suite
Tests:
- Tunnel Manager status and discovery
- Lifecycle state transitions (idle, running, stopped)
- Edge PoP Colocation detection & latency fields
- API endpoint integration: /api/tunnel/status, /api/host-info
"""

import sys
import unittest
from pathlib import Path

AUTH_ROOT = Path(__file__).resolve().parent.parent
if str(AUTH_ROOT) not in sys.path:
    sys.path.insert(0, str(AUTH_ROOT))

from core.tunnel_manager import CloudflaredTunnelManager, tunnel_manager, COLO_LOCATIONS
from fastapi.testclient import TestClient
from server import app


class TestAuthTunnelManager(unittest.TestCase):
    def setUp(self):
        self.mgr = CloudflaredTunnelManager()
        self.client = TestClient(app)

    def tearDown(self):
        self.mgr.stop()

    def test_initial_status_structure(self):
        st = self.mgr.get_status()
        self.assertFalse(st["running"])
        self.assertEqual(st["status"], "idle")
        self.assertIsNone(st["url"])
        self.assertIsNone(st["error"])
        self.assertIn("installed", st)
        self.assertIn("platform", st)
        self.assertIn("installCommand", st)
        self.assertIsInstance(st["installCommand"], str)
        self.assertGreater(len(st["installCommand"]), 0)
        self.assertEqual(st["edgeIpVersion"], "auto")
        self.assertIsNone(st["edgeColo"])
        self.assertIsNone(st["edgeLocation"])
        self.assertIsNone(st["latencyMs"])

    def test_find_cloudflared(self):
        bin_path = self.mgr.find_cloudflared()
        if bin_path:
            self.assertIsInstance(bin_path, str)
            self.assertTrue(Path(bin_path).exists())

    def test_lifecycle_offline_state(self):
        # Simulate running state
        self.mgr.status = "running"
        self.mgr.tunnel_url = "https://mock-auth-test.trycloudflare.com"
        self.mgr.edge_colo = "SIN"
        self.mgr.edge_location = COLO_LOCATIONS.get("SIN")
        self.mgr.latency_ms = 45
        st = self.mgr.get_status()
        self.assertTrue(st["running"])
        self.assertEqual(st["url"], "https://mock-auth-test.trycloudflare.com")
        self.assertEqual(st["edgeColo"], "SIN")
        self.assertEqual(st["edgeLocation"], "Singapore")
        self.assertEqual(st["latencyMs"], 45)

        # Stop
        st2 = self.mgr.stop()
        self.assertFalse(st2["running"])
        self.assertIsNone(st2["url"])
        self.assertEqual(st2["status"], "idle")
        self.assertIsNone(st2["edgeColo"])
        self.assertIsNone(st2["edgeLocation"])
        self.assertIsNone(st2["latencyMs"])

    def test_colo_locations_mapping(self):
        self.assertIn("HAN", COLO_LOCATIONS)
        self.assertIn("SGN", COLO_LOCATIONS)
        self.assertIn("HKG", COLO_LOCATIONS)
        self.assertIn("SIN", COLO_LOCATIONS)
        self.assertEqual(COLO_LOCATIONS["HAN"], "Hà Nội (Việt Nam)")
        self.assertEqual(COLO_LOCATIONS["SGN"], "TP. Hồ Chí Minh (Việt Nam)")

    def test_api_tunnel_status_endpoint(self):
        resp = self.client.get("/api/tunnel/status")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertIn("running", data)
        self.assertIn("status", data)
        self.assertIn("installCommand", data)
        self.assertIn("edgeIpVersion", data)
        self.assertIn("edgeColo", data)
        self.assertIn("edgeLocation", data)
        self.assertIn("latencyMs", data)

    def test_api_host_info_includes_tunnel(self):
        resp = self.client.get("/api/host-info")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertIn("tunnel", data)
        self.assertIn("active_url", data)


if __name__ == "__main__":
    unittest.main()
