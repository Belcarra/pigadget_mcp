import json
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from pigadget_mcp import server


class Timer:
    timers = []

    def __init__(self, delay, callback, args=()):
        self.delay, self.callback, self.args = delay, callback, args
        self.cancelled = False
        self.timers.append(self)

    def start(self):
        pass

    def cancel(self):
        self.cancelled = True

    def fire(self):
        self.callback(*self.args)


class IdleTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        Timer.timers = []
        patches = [
            patch.object(server, "GADGET_ROOT", self.root / "configfs"),
            patch.object(server, "SURVEY_STATE_PATH", self.root / "state.json"),
            patch.object(server, "PROBE_PROFILE_PATH", self.root / "probe.json"),
            patch.object(server, "IDLE_SURVEY_ENABLED", True),
            patch.object(server, "TEST_GADGET", None),
            patch.object(server, "RESTORE_TIMER", None),
            patch.object(server, "RESTORE_GENERATION", 0),
            patch.object(server, "_default_serial_number", return_value="000000001234abcd"),
            patch.object(server.socket, "gethostname", return_value="pi1"),
            patch.object(server.threading, "Timer", Timer),
            patch.object(server, "_gadgetconfig", side_effect=self.command),
            patch.object(server, "gadget_status", side_effect=lambda *_: {"identity": server._identity()}),
        ]
        for item in patches:
            item.start()
            self.addCleanup(item.stop)

    def create(self, name, serial="old", enabled=False):
        path = server.GADGET_ROOT / name
        (path / "strings/0x409").mkdir(parents=True, exist_ok=True)
        (path / "strings/0x409/serialnumber").write_text(serial)
        (path / "UDC").write_text("dummy" if enabled else "")
        (path / "idVendor").write_text("0x15ec")
        (path / "idProduct").write_text("0xa001" if name == server.PROBE_NAME else "0xd021")

    def command(self, args):
        if args[0] == "--disable":
            for path in server.GADGET_ROOT.glob("*/UDC"):
                path.write_text("")
        elif args[0] == "--remove":
            shutil.rmtree(server.GADGET_ROOT / args[1], ignore_errors=True)
        elif args[0] == "--add":
            data = json.loads(Path(args[1]).read_text())
            for name, profile in data.items():
                serial = args[args.index("--serialnumber") + 1] if "--serialnumber" in args else profile["strings"]["0x409"]["serialnumber"]
                self.create(name, serial)
        elif args[0] == "--enable":
            (server.GADGET_ROOT / args[1] / "UDC").write_text("dummy")
        return {"ok": True, "stderr": "", "stdout": "", "returncode": 0}

    def test_boot_enables_survey_with_stable_serial(self):
        server._initialize_idle_survey()
        self.assertEqual(Timer.timers[-1].delay, 0)
        Timer.timers[-1].fire()
        self.assertEqual(server._current_name(), server.PROBE_NAME)
        self.assertEqual(server._identity()["serial_number"], "000000001234abcd")

    def test_test_enable_removes_probe_and_unload_restores_after_five_seconds(self):
        self.create(server.PROBE_NAME, enabled=True)
        self.create("EEM")
        result = server.gadget_enable("EEM")
        self.assertFalse((server.GADGET_ROOT / server.PROBE_NAME).exists())
        self.assertEqual(result["serial_number"], "000000001234abcd")
        result = server.gadget_unload()
        self.assertEqual(result["survey_restore_in_seconds"], 5)
        self.assertFalse((server.GADGET_ROOT / "EEM").exists())
        self.assertIsNone(server._current_name())
        Timer.timers[-1].fire()
        self.assertEqual(server._current_name(), server.PROBE_NAME)

    def test_new_test_cancels_even_an_already_dispatched_restore_callback(self):
        self.create("EEM", enabled=True)
        server._claim_test("EEM")
        server.gadget_disable()
        old_timer = Timer.timers[-1]
        server.gadget_enable("EEM", serial_number="explicit-serial")
        old_timer.fire()
        self.assertTrue(old_timer.cancelled)
        self.assertEqual(server._current_name(), "EEM")
        self.assertEqual(server._identity()["serial_number"], "explicit-serial")

    def test_service_restart_preserves_soft_disconnected_test(self):
        self.create("EEM")
        server._claim_test("EEM")
        server._initialize_idle_survey()
        self.assertEqual(server.TEST_GADGET, "EEM")
        self.assertFalse(Timer.timers)

    def test_host_observation_preserves_loaded_test_lease(self):
        self.create("EEM")
        server._claim_test("EEM")
        server.gadget_record_host("laptop", "2026-01-01T00:00:00Z")
        self.assertEqual(server._survey_state()["test_gadget"], "EEM")

    def test_new_boot_replaces_previous_test_with_survey(self):
        self.create("EEM", enabled=True)
        server._claim_test("EEM")
        server._update_survey_state(boot_id="previous-boot")
        server._initialize_idle_survey()
        Timer.timers[-1].fire()
        self.assertEqual(server._current_name(), server.PROBE_NAME)
        self.assertIsNone(server.TEST_GADGET)

    def test_profile_key_is_selected_and_explicit_serial_read_back(self):
        profile = self.root / "different-filename.json"
        profile.write_text(json.dumps({"EEM": {"strings": {"0x409": {"serialnumber": "old"}}}}))
        self.create(server.PROBE_NAME, enabled=True)
        with patch.object(server, "_resolve_profile", return_value=str(profile)):
            result = server.gadget_configure_profile(str(profile), overrides={"serialnumber": "custom-test-serial"})
        self.assertEqual(server._current_name(), "EEM")
        self.assertEqual(result["identity"]["serial_number"], "custom-test-serial")

    def test_configfs_status_matches_bound_identity(self):
        self.create(server.PROBE_NAME, serial="stable", enabled=True)
        state = server._configfs_query()
        self.assertEqual(state["current_gadget"], server._identity()["gadget_name"])
        self.assertEqual(state["defined_gadgets"], [server.PROBE_NAME])

    def test_cli_query_parses_command_results(self):
        result = {"ok": True, "stderr": "", "stdout": "Currently configured: EEM\n", "returncode": 0}
        with patch.object(server, "_gadgetconfig", return_value=result):
            self.assertEqual(server._query()["current_gadget"], "EEM")

    def test_bundle_selects_requested_gadget_without_renaming_others(self):
        profile = self.root / "bundle.json"
        profile.write_text(json.dumps({name: {"strings": {"0x409": {"serialnumber": "old"}}} for name in ("ECM", "EEM")}))
        with patch.object(server, "_resolve_profile", return_value=str(profile)):
            server.gadget_configure_profile(str(profile), name="EEM")
        self.assertEqual(server._current_name(), "EEM")
        self.assertEqual(server.TEST_GADGET, "EEM")
        self.assertTrue((server.GADGET_ROOT / "ECM").is_dir())
