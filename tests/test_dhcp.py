import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from pigadget_mcp import dhcp, server
import test_protocol as protocol_tests


class HookTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.directory = self.root / "usb1"
        self.directory.mkdir()
        dhcp._write(self.directory / "session.json", {"interface": "usb1", "ifindex": 7,
                    "token": "owned", "active": True, "run_id": "test", "gadget_name": "test"})
        for item in (patch.object(dhcp, "ROOT", self.root), patch.object(dhcp, "_secure_directory"),
                     patch.object(dhcp, "_ifindex", return_value=7), patch.object(dhcp, "_cidrs", return_value=[])):
            item.start()
            self.addCleanup(item.stop)
        self.env = {"interface": "usb1", "reason": "BOUND", "new_ip_address": "192.168.188.2",
                    "new_subnet_mask": "255.255.255.248", "new_routers": "192.168.188.3",
                    "new_domain_name_servers": "203.0.113.1", "new_dhcp_lease_time": "600"}

    def test_only_offered_address_is_applied_options_are_evidence(self):
        with patch.object(dhcp, "_addresses", return_value=[]), patch.object(dhcp, "_run") as run:
            lease = dhcp.apply_hook(self.directory, "owned", self.env)
        self.assertEqual(lease["address"], "192.168.188.2/29")
        self.assertEqual(lease["options"]["routers"], "192.168.188.3")
        run.assert_called_once_with(["ip", "address", "replace", "192.168.188.2/29", "dev", "usb1"])

    def test_renewal_replaces_only_previous_owned_address(self):
        dhcp._write(self.directory / "lease.json", {"address": "192.168.188.4/29"})
        with patch.object(dhcp, "_addresses", return_value=[]), \
                patch.object(dhcp, "_cidrs", return_value=["192.168.188.4/29"]), patch.object(dhcp, "_run") as run:
            dhcp.apply_hook(self.directory, "owned", {**self.env, "reason": "RENEW"})
        self.assertEqual(run.call_args_list[0].args[0], ["ip", "address", "del", "192.168.188.4/29", "dev", "usb1"])

    def test_oem_link_local_lease_accepted_but_apipa_refused(self):
        env = {**self.env, "new_ip_address": "169.254.1.2"}
        with patch.object(dhcp, "_addresses", return_value=[]), patch.object(dhcp, "_run") as run:
            lease = dhcp.apply_hook(self.directory, "owned", env)
        self.assertEqual(lease["address"], "169.254.1.2/29")
        run.assert_called_once_with(["ip", "address", "replace", "169.254.1.2/29", "dev", "usb1"])
        with patch.object(dhcp, "_run") as run, self.assertRaises(dhcp.DhcpError):
            dhcp.apply_hook(self.directory, "owned", {**env, "new_subnet_mask": "255.255.0.0"})
        run.assert_not_called()

    def test_link_local_lease_still_rejects_management_overlap(self):
        rows = [{"ifname": "eth0", "addr_info": [{"family": "inet", "local": "169.254.1.1", "prefixlen": 29}]}]
        with patch.object(dhcp, "_addresses", return_value=rows), patch.object(dhcp, "_run") as run, self.assertRaises(dhcp.DhcpError):
            dhcp.apply_hook(self.directory, "owned", {**self.env, "new_ip_address": "169.254.1.2"})
        run.assert_not_called()

    def test_management_overlap_and_default_prefix_rejected(self):
        for changes, addresses in [({"new_subnet_mask": "0.0.0.0"}, []),
                                   ({}, [{"ifname": "eth0", "addr_info": [{"family": "inet", "local": "192.168.188.1", "prefixlen": 24}]}])]:
            with self.subTest(changes=changes), patch.object(dhcp, "_addresses", return_value=addresses), \
                    patch.object(dhcp, "_run") as run, self.assertRaises(dhcp.DhcpError):
                dhcp.apply_hook(self.directory, "owned", {**self.env, **changes})
            run.assert_not_called()

    def test_stale_hook_token_and_reused_interface_refused(self):
        with self.assertRaises(dhcp.DhcpError):
            dhcp.apply_hook(self.directory, "wrong", self.env)
        with patch.object(dhcp, "_ifindex", return_value=8), self.assertRaises(dhcp.DhcpError):
            dhcp.apply_hook(self.directory, "owned", self.env)

    def test_expiry_removes_only_owned_address(self):
        dhcp._write(self.directory / "lease.json", {"address": "192.168.188.2/29"})
        with patch.object(dhcp, "_cidrs", return_value=["192.168.188.2/29", "192.0.2.2/24"]), patch.object(dhcp, "_run") as run:
            lease = dhcp.apply_hook(self.directory, "owned", {"interface": "usb1", "reason": "EXPIRE"})
        self.assertIsNone(lease["address"])
        run.assert_called_once_with(["ip", "address", "del", "192.168.188.2/29", "dev", "usb1"])

    def test_cached_lease_is_not_a_fallback(self):
        with self.assertRaisesRegex(dhcp.DhcpError, "cached lease"), patch.object(dhcp, "_run") as run:
            dhcp.apply_hook(self.directory, "owned", {**self.env, "reason": "TIMEOUT"})
        run.assert_not_called()

    def test_other_run_cannot_stop_session(self):
        with self.assertRaisesRegex(dhcp.DhcpError, "another run"), patch.object(dhcp, "_run") as run:
            dhcp.stop("usb1", "another")
        run.assert_not_called()

    def test_management_interfaces_and_traversal_refused(self):
        for interface in ("eth0", "wlan0", "../usb0", "usb0;reboot"):
            with self.subTest(interface=interface), self.assertRaises(dhcp.DhcpError):
                dhcp.status(interface)


class DhcpProtocolTests(unittest.TestCase):
    setUp = protocol_tests.ProtocolTests.setUp
    create = protocol_tests.ProtocolTests.create
    interfaces = protocol_tests.ProtocolTests.interfaces
    command = protocol_tests.ProtocolTests.command

    def test_configure_dhcp_and_unload_release(self):
        with patch.object(dhcp, "validate_request"), patch.object(dhcp, "start", return_value={"status": "bound", "address": "192.168.188.2/29"}) as start:
            result = server.gadget_configure_protocol("eem", "1777", "0002", ipv4="dhcpc", run_id="run-1")
        start.assert_called_once_with("usb1", "run-1", "mcp_test", "000000001234abcd", 30)
        self.assertEqual(result["dhcp"]["address"], "192.168.188.2/29")
        self.assertEqual(result["static_ip"], [])
        with patch.object(dhcp, "stop_gadget", return_value=[]) as stop:
            server.gadget_unload()
        stop.assert_called_once_with("mcp_test")

    def test_failed_lease_restores_idle_and_cleans_client(self):
        with patch.object(dhcp, "validate_request"), patch.object(dhcp, "start", side_effect=dhcp.DhcpError("timeout")), \
                patch.object(dhcp, "stop_gadget", return_value=[]) as stop, self.assertRaises(server.GadgetError):
            server.gadget_configure_protocol("eem", "1777", "0002", ipv4="dhcp")
        self.assertIn(unittest.mock.call("mcp_test"), stop.call_args_list)
        self.assertFalse((server.GADGET_ROOT / "mcp_test").exists())

    def test_dhcp_api_uses_configfs_interface_not_usb0_assumption(self):
        server.gadget_configure_protocol("eem", "1777", "0002")
        with patch.object(dhcp, "start", return_value={"status": "bound"}) as start:
            server.network_dhcp_start("test-run")
        self.assertEqual(start.call_args.args[0], "usb1")
        with self.assertRaises(server.GadgetError):
            server.network_dhcp_start("test-run", interface="eth0")
