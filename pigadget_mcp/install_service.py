#!/usr/bin/env python3
from __future__ import annotations

import argparse
import sys
import shutil
import subprocess
from pathlib import Path


SERVICE_NAME = "pigadget-mcp.service"


def run(command: list[str]) -> None:
    subprocess.run(command, check=True)


def default_unit_src() -> str:
    candidates = [
        Path(__file__).resolve().parent.parent / "service" / SERVICE_NAME,
        Path.cwd() / "service" / SERVICE_NAME,
        Path(sys.prefix) / "share" / "pigadget-mcp" / "service" / SERVICE_NAME,
        Path("/usr/local/share/pigadget-mcp/service") / SERVICE_NAME,
        Path("/usr/share/pigadget-mcp/service") / SERVICE_NAME,
    ]
    for candidate in candidates:
        if candidate.exists():
            return str(candidate)
    return str(candidates[0])


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Install pigadget-mcp systemd unit")
    parser.add_argument(
        "--unit-src",
        default=default_unit_src(),
        help="Source systemd unit file",
    )
    parser.add_argument(
        "--unit-dst-dir",
        default="/etc/systemd/system",
        help="Destination systemd unit directory",
    )
    parser.add_argument("--enable", action="store_true", help="Enable the service")
    parser.add_argument("--start", action="store_true", help="Start or restart the service")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    src = Path(args.unit_src)
    if not src.exists():
        raise FileNotFoundError(src)
    dst = Path(args.unit_dst_dir) / SERVICE_NAME
    dst.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(src, dst)
    run(["systemctl", "daemon-reload"])
    if args.enable:
        run(["systemctl", "enable", SERVICE_NAME])
    if args.start:
        run(["systemctl", "restart", SERVICE_NAME])
    print(dst)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
