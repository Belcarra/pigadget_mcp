import unittest
from pathlib import Path
from unittest.mock import patch

import commentjson

from pigadget_mcp import server
import test_idle
from test_idle import Timer


class ProtocolTests(unittest.TestCase):
    create = test_idle.IdleTests.create

    def setUp(self):
        test_idle.IdleTests.setUp(self)
        server.GADGET_ROOT.mkdir()
        udc = self.root / "udc"
        (udc / "dummy").mkdir(parents=True)
        self.failure = None
        self.created = None
        for item in [patch.object(server, "UDC_ROOT", udc),
                     patch.object(server, "_protocol_support", return_value={protocol: {"available": True}
                                  for protocol in ("eem", "ecm", "rndis", "ncm")}),
                     patch.object(server, "_usb_interfaces", side_effect=self.interfaces)]:
            item.start()
            self.addCleanup(item.stop)

    def interfaces(self):
        return {"interfaces": [{"name": "usb1", "state": "DOWN"}, {"name": "usb0", "state": "UP"}]}

    def command(self, args):
        if self.failure == args[0]:
            self.failure = None
            return {"ok": False, "stderr": "injected failure", "stdout": "", "returncode": 1}
        if args[0] == "--add":
            data = commentjson.loads(Path(args[1]).read_text())
            self.created = data
            for name, profile in data.items():
                serial = args[args.index("--serialnumber") + 1] if "--serialnumber" in args else profile["strings"]["0x409"]["serialnumber"]
                self.create(name, serial)
                for key, value in profile.items():
                    if isinstance(value, str):
                        (server.GADGET_ROOT / name / key).write_text(value)
                for key, value in profile.get("strings", {}).get("0x409", {}).items():
                    (server.GADGET_ROOT / name / "strings/0x409" / key).write_text(value)
                for function in profile.get("functions", {}):
                    path = server.GADGET_ROOT / name / "functions" / function
                    path.mkdir(parents=True)
                    (path / "ifname").write_text("usb1")
            return {"ok": True, "stderr": "", "stdout": "", "returncode": 0}
        return test_idle.IdleTests.command(self, args)

    def test_four_single_function_protocols_and_cleanup(self):
        for protocol in ("eem", "ecm", "rndis", "ncm"):
            with self.subTest(protocol=protocol):
                self.create(server.PROBE_NAME, enabled=True)
                result = server.gadget_configure_protocol(protocol.upper(), "1777", "0002")
                self.assertEqual(result["serial_number"], "000000001234abcd")
                self.assertEqual(result["identity"]["vid"], "0x1777")
                self.assertEqual(result["usb_interface"], "usb1")
                self.assertEqual(list(self.created["mcp_test"]["functions"]), [protocol + ".usb0"])
                self.assertEqual(list(self.created["mcp_test"]["configs"]), ["c.1"])
                self.assertEqual(result["descriptors"]["strings"]["product"], "CDC " + protocol.upper())
                self.assertFalse((server.GADGET_ROOT / server.PROBE_NAME).exists())
                self.assertEqual(server.gadget_unload()["survey_restore_in_seconds"], 5)
                Timer.timers[-1].fire()
                self.assertEqual(server._current_name(), server.PROBE_NAME)

    def test_explicit_descriptors_and_address_use_actual_interface(self):
        with patch.object(server, "_configure_static_ip", return_value=[{"ok": True}]) as configure:
            result = server.gadget_configure_protocol("eem", "0x1777", "0002", ipv4="192.168.188.2/24",
                                                     serial_number="custom", manufacturer="OEM", product="OEM EEM")
        configure.assert_called_once_with("usb1", "192.168.188.2/24")
        self.assertEqual(result["serial_number"], "custom")
        self.assertEqual(result["descriptors"]["strings"]["manufacturer"], "OEM")

    def test_bad_inputs_leave_idle_probe_untouched(self):
        self.create(server.PROBE_NAME, enabled=True)
        cases = [{"protocol": "composite"}, {"vid": "177"}, {"pid": "../bad"},
                 {"name": server.PROBE_NAME}, {"name": "../bad"}, {"qmult": 0},
                 {"ipv4": "eth0"}, {"ipv4": "192.168.188.2"}, {"ipv4": "::1/128"},
                 {"serial_number": ""}, {"manufacturer": "bad\nstring"},
                 {"dev_addr": "01:00:00:00:00:01"}, {"host_addr": "00:00:00:00:00:00"}]
        for overrides in cases:
            with self.subTest(overrides=overrides):
                args = {"protocol": "eem", "vid": "1777", "pid": "0002", **overrides}
                with self.assertRaises(server.GadgetError):
                    server.gadget_configure_protocol(**args)
                self.assertEqual(server._current_name(), server.PROBE_NAME)
                self.assertIsNone(server.TEST_GADGET)

    def test_unsupported_kernel_leaves_probe_untouched(self):
        self.create(server.PROBE_NAME, enabled=True)
        with patch.object(server, "_protocol_support", return_value={"ncm": {"available": False, "error": "missing module"}}):
            with self.assertRaisesRegex(server.GadgetError, "protocol unavailable"):
                server.gadget_configure_protocol("ncm", "1777", "0002")
        self.assertEqual(server._current_name(), server.PROBE_NAME)

    def test_active_and_disconnected_tests_are_not_replaced(self):
        for enabled in (False, True):
            self.create("existing", enabled=enabled)
            server._claim_test("existing")
            with self.assertRaisesRegex(server.GadgetError, "already loaded"):
                server.gadget_configure_protocol("eem", "1777", "0002")
            self.assertTrue((server.GADGET_ROOT / "existing").exists())

    def test_stale_definition_is_not_silently_reused(self):
        self.create("mcp_test")
        with self.assertRaisesRegex(server.GadgetError, "already exists"):
            server.gadget_configure_protocol("eem", "1777", "0002")

    def test_setup_failures_remove_test_and_restore_idle(self):
        for operation in ("--add", "--enable"):
            self.create(server.PROBE_NAME, enabled=True)
            self.failure = operation
            with self.assertRaisesRegex(server.GadgetError, "injected failure"):
                server.gadget_configure_protocol("eem", "1777", "0002")
            self.assertFalse((server.GADGET_ROOT / "mcp_test").exists())
            self.assertIsNone(server.TEST_GADGET)
            Timer.timers[-1].fire()
            self.assertEqual(server._current_name(), server.PROBE_NAME)

    def test_ip_failure_is_not_reported_as_success(self):
        with patch.object(server, "_configure_static_ip", return_value=[{"ok": False, "stderr": "bad IP"}]):
            with self.assertRaisesRegex(server.GadgetError, "static IPv4 configuration failed"):
                server.gadget_configure_protocol("eem", "1777", "0002", ipv4="192.168.188.2/24")
        self.assertIsNone(server.TEST_GADGET)
        Timer.timers[-1].fire()
        self.assertEqual(server._current_name(), server.PROBE_NAME)

    def test_actual_comment_profile_loads_and_configures(self):
        source = Path(__file__).with_name("fixtures") / "eem-15ec-f021.json"
        self.assertEqual(list(server._load_profile(source)), ["EEM"])
        with patch.object(server, "_resolve_profile", return_value=str(source)):
            result = server.gadget_configure_profile(str(source))
        self.assertEqual(result["identity"]["gadget_name"], "EEM")

    def test_comment_markers_inside_strings_are_preserved(self):
        source = self.root / "comment.json"
        source.write_text('# heading\n{"EEM": {"product": "http://example/#device"}} // tail\n')
        self.assertEqual(server._load_profile(source)["EEM"]["product"], "http://example/#device")

    def test_invalid_profile_does_not_remove_probe(self):
        self.create(server.PROBE_NAME, enabled=True)
        source = self.root / "invalid.json"
        source.write_text("[]")
        with patch.object(server, "_resolve_profile", return_value=str(source)):
            with self.assertRaises(server.GadgetError):
                server.gadget_configure_profile(str(source))
        self.assertEqual(server._current_name(), server.PROBE_NAME)
