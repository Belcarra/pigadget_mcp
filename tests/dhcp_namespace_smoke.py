"""Explicit root-only DHCP handshake test using a temporary veth/network namespace."""
import argparse
import hashlib
import json
import os
import shutil
import subprocess
import tempfile
import uuid
from pathlib import Path

from pigadget_mcp import dhcp


def run(args):
    return subprocess.check_output(args, text=True).strip()


def management():
    return {"default_routes": run(["ip", "-4", "route", "show", "default"]),
            "addresses": {row["ifname"]: sorted((ip["local"], ip["prefixlen"]) for ip in row.get("addr_info", []) if ip.get("family") == "inet")
                          for row in json.loads(run(["ip", "-j", "-4", "address", "show"]))
                          if row["ifname"] != "lo" and not row["ifname"].startswith("usb")},
            "dns_hash": hashlib.sha256(Path("/etc/resolv.conf").read_bytes()).hexdigest()}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--link-local", action="store_true", help="Exercise the OEM 169.254.1.0/29 subnet")
    args = parser.parse_args()
    server_ip = "169.254.1.1" if args.link_local else "192.0.2.1"
    client_ip = "169.254.1.2" if args.link_local else "192.0.2.2"
    prefix, mask = (29, "255.255.255.248") if args.link_local else (30, "255.255.255.252")
    if os.geteuid() != 0 or not shutil.which("dnsmasq"):
        raise RuntimeError("explicit root invocation and dnsmasq are required")
    token = uuid.uuid4().hex[:8]
    namespace = "pgdhcp-" + token
    interface = "usb" + str(int(token, 16) % 90000 + 10000)
    directory = dhcp.ROOT / interface
    assert not directory.exists() and not Path("/sys/class/net", interface).exists()
    before = management()
    created, server = False, None
    try:
        run(["ip", "netns", "add", namespace])
        created = True
        run(["ip", "link", "add", interface, "type", "veth", "peer", "name", "srv0", "netns", namespace])
        run(["nmcli", "device", "set", interface, "managed", "no"])
        run(["ip", "-n", namespace, "link", "set", "lo", "up"])
        run(["ip", "-n", namespace, "link", "set", "srv0", "up"])
        run(["ip", "-n", namespace, "address", "add", "%s/%s" % (server_ip, prefix), "dev", "srv0"])
        with tempfile.TemporaryFile() as log:
            server = subprocess.Popen(["ip", "netns", "exec", namespace, "dnsmasq", "--no-daemon",
                "--conf-file=/dev/null", "--port=0", "--interface=srv0", "--bind-interfaces",
                "--dhcp-authoritative", "--dhcp-range=%s,%s,%s,5m" % (client_ip, client_ip, mask),
                "--dhcp-option=3," + server_ip, "--dhcp-option=6,203.0.113.1", "--log-dhcp"], stdout=log, stderr=log)
            lease = dhcp.start(interface, token, "dhcp-selftest", "isolated-test", timeout=20)
            assert lease["status"] == "bound" and lease["address"] == "%s/%s" % (client_ip, prefix), lease
            assert lease["lease"]["options"]["routers"] == server_ip, lease
            assert management() == before, (before, management())
            stopped = dhcp.stop(interface, token)
            assert stopped["status"] == "stopped" and not stopped["address"], stopped
            assert management() == before
            print(json.dumps({"lease": lease, "cleanup": stopped, "management_unchanged": True}, indent=2))
    finally:
        if directory.exists():
            dhcp.stop(interface, token)
        if server:
            server.terminate()
            server.wait(timeout=5)
        if Path("/sys/class/net", interface).exists():
            run(["ip", "link", "delete", interface])
        if created:
            run(["ip", "netns", "delete", namespace])
        if directory.exists():
            shutil.rmtree(directory)


if __name__ == "__main__":
    main()
