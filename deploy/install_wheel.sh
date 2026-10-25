#!/bin/bash
set -euo pipefail
wheel="$1"
allow_busy="${2:-no}"
python="$(head -n1 /usr/local/bin/pigadget-mcp)"
python="${python#\#!}"
if [ "$allow_busy" != yes ]; then
    "$python" -c 'from pigadget_mcp import server; current=server._current_name(); saved=server._survey_state().get("test_gadget"); assert not saved and current in (None, server.PROBE_NAME), "active test: service update deferred"'
fi
"$python" -m pip install --break-system-packages --no-index --no-deps --force-reinstall "$wheel"
nm_config="$("$python" -c 'import sys; from pathlib import Path; paths=[Path(sys.prefix)/"share", Path("/usr/local/share"), Path("/usr/share")]; print(next(p/"pigadget-mcp/service/pigadget-mcp-networkmanager.conf" for p in paths if (p/"pigadget-mcp/service/pigadget-mcp-networkmanager.conf").is_file()))')"
if systemctl is-active --quiet NetworkManager; then
    install -D -m 0644 "$nm_config" /etc/NetworkManager/conf.d/90-pigadget-mcp-usb.conf
    nmcli general reload conf
fi
"$python" -c 'from pigadget_mcp import dhcp; from pigadget_mcp.version import VERSION; print(VERSION, dhcp.backend()); assert dhcp.backend()["available"]'
systemctl restart pigadget-mcp
systemctl is-active pigadget-mcp
