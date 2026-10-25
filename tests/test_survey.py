import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from pigadget_mcp import server


class HostRecordTests(unittest.TestCase):
    def test_record_survives_reload_and_older_observation_does_not_replace_it(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(server, "SURVEY_STATE_PATH", Path(directory) / "survey.json"):
            server.gadget_record_host("laptop", "2026-01-02T00:00:00Z")
            server.gadget_record_host("old-laptop", "2026-01-01T00:00:00Z")
            self.assertEqual(server._survey_state()["last_host"]["windows_host"], "laptop")

    def test_probe_cannot_replace_active_gadget_in_idle_mode(self):
        with patch.object(server, "_query", return_value={"current_gadget": "EEM", "commands": {"current": {"ok": True}}}), patch.object(server, "_gadgetconfig") as command:
            with self.assertRaises(server.GadgetError):
                server.gadget_probe_enable(require_idle=True)
            command.assert_not_called()

    def test_cleanup_cannot_disable_another_gadget(self):
        with patch.object(server, "_query", return_value={"current_gadget": "EEM", "commands": {"current": {"ok": True}}}), patch.object(server, "_gadgetconfig") as command:
            with self.assertRaises(server.GadgetError):
                server.gadget_probe_disable(only_probe=True)
            command.assert_not_called()
