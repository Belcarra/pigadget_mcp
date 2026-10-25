"""Owned ISC dhclient sessions and an address-only USB lease hook."""
import ipaddress
import json
import os
import re
import shutil
import subprocess
import sys
import time
import uuid
from pathlib import Path


ROOT = Path("/run/pigadget-mcp/dhcp")


class DhcpError(Exception):
    pass


def backend():
    client = shutil.which("dhclient") or ("/usr/sbin/dhclient" if Path("/usr/sbin/dhclient").is_file() else None)
    hook = Path(sys.executable).parent / "pigadget-mcp-dhcp-hook"
    hook = str(hook) if hook.is_file() else shutil.which("pigadget-mcp-dhcp-hook")
    return {"name": "isc-dhclient", "available": bool(client and hook), "client": client,
            "hook": hook, "address_only": True, "preserves_default_routes_and_dns": True}


def _directory(interface):
    if not re.fullmatch(r"usb[0-9]+", interface):
        raise DhcpError("only usbN interfaces are permitted")
    return ROOT / interface


def _secure_directory(path):
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    if path.is_symlink() or path.stat().st_uid != 0 or path.stat().st_mode & 0o077:
        raise DhcpError("DHCP state directory must be root-owned and mode 0700")


def _read(path):
    try:
        return json.loads(path.read_text())
    except (OSError, ValueError):
        return {}


def _write(path, data):
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(data), encoding="utf-8")
    temporary.replace(path)


def _run(argv, timeout=10):
    result = subprocess.run(argv, capture_output=True, text=True, errors="replace", timeout=timeout, check=False)
    if result.returncode:
        raise DhcpError(result.stderr.strip() or result.stdout.strip() or "command failed")
    return result.stdout


def _ifindex(interface):
    try:
        return int(Path("/sys/class/net", interface, "ifindex").read_text())
    except (OSError, ValueError):
        return None


def _addresses(interface=None):
    args = ["ip", "-j", "-4", "address", "show"]
    if interface:
        args += ["dev", interface]
    return json.loads(_run(args))


def _cidrs(interface):
    if _ifindex(interface) is None:
        return []
    return ["%s/%s" % (ip["local"], ip["prefixlen"]) for row in _addresses(interface)
            for ip in row.get("addr_info", []) if ip.get("family") == "inet"]


def _owns(meta):
    try:
        args = Path("/proc", str(meta["pid"]), "cmdline").read_bytes().decode().split("\0")
    except (OSError, KeyError):
        return False
    directory = _directory(meta["interface"])
    return bool(args and Path(args[0]).name == "dhclient" and str(directory / "client.conf") in args
                and str(directory / "client.pid") in args and meta["interface"] in args)


def status(interface):
    directory = _directory(interface)
    meta, lease = _read(directory / "session.json"), _read(directory / "lease.json")
    running = _owns(meta) if meta else False
    address = lease.get("address")
    present = bool(address and _ifindex(interface) == meta.get("ifindex") and address in _cidrs(interface))
    state = "failed" if lease.get("error") else "bound" if running and present else "waiting" if running else "cleanup_required" if present else "stopped"
    try:
        with (directory / "client.log").open("rb") as log:
            log.seek(0, 2)
            log.seek(max(0, log.tell() - 4000))
            tail = log.read().decode("utf-8", errors="replace")
    except OSError:
        tail = ""
    return {"status": state, "backend": "isc-dhclient", "interface": interface,
            "run_id": meta.get("run_id"), "gadget_name": meta.get("gadget_name"),
            "serial_number": meta.get("serial_number"), "pid": meta.get("pid") if running else None,
            "address": address if present else None, "lease": lease, "log_tail": tail}


def _remove_address(meta, lease):
    interface, address = meta["interface"], lease.get("address")
    if address and _ifindex(interface) == meta.get("ifindex") and address in _cidrs(interface):
        _run(["ip", "address", "del", address, "dev", interface])
    lease["last_address"] = address or lease.get("last_address")
    lease["address"] = None


def stop(interface, run_id=None):
    directory = _directory(interface)
    meta = _read(directory / "session.json")
    if not meta:
        return status(interface)
    if run_id is not None and run_id != meta.get("run_id"):
        raise DhcpError("another run owns this interface's DHCP session")
    if _owns(meta):
        _run(_command(meta, release=True), timeout=15)
        deadline = time.monotonic() + 5
        while _owns(meta) and time.monotonic() < deadline:
            time.sleep(0.1)
        if _owns(meta):
            raise DhcpError("DHCP client did not stop; gadget retained for recovery")
    elif meta.get("pid") and Path("/proc", str(meta["pid"]), "cmdline").exists():
        if Path("/proc", str(meta["pid"]), "cmdline").read_bytes():
            raise DhcpError("saved PID belongs to another process; refusing to signal it")
    meta["active"] = False
    meta["last_pid"] = meta.get("pid")
    meta["pid"] = None
    _write(directory / "session.json", meta)
    lease = _read(directory / "lease.json")
    _remove_address(meta, lease)
    lease.update(reason="STOP", error=None)
    _write(directory / "lease.json", lease)
    return status(interface)


def stop_gadget(name):
    results = []
    if name:
        for path in ROOT.glob("usb*/session.json"):
            meta = _read(path)
            if meta.get("gadget_name") == name:
                results.append(stop(meta["interface"]))
    return results


def _command(meta, release=False):
    directory = _directory(meta["interface"])
    info = backend()
    if not info["available"]:
        raise DhcpError("managed DHCP backend is unavailable")
    return [info["client"], "-4", "-r" if release else "-d", "-v",
            "-pf", str(directory / "client.pid"), "-lf", str(directory / "client.leases"),
            "-cf", str(directory / "client.conf"), "-sf", info["hook"],
            "-e", "PIGADGET_DHCP_DIR=" + str(directory),
            "-e", "PIGADGET_DHCP_TOKEN=" + meta["token"], meta["interface"]]


def _external_clients(interface):
    interfaces = {path.name for path in Path("/sys/class/net").glob("*")}
    for path in Path("/proc").glob("[0-9]*/cmdline"):
        try:
            args = path.read_bytes().decode(errors="replace").split("\0")
            if interface in args and (Path(args[0]).name in {"dhclient", "udhcpc"} or "udhcpc" in args):
                return True
            if Path(args[0]).name == "dhclient" and not interfaces.intersection(args):
                return True
        except OSError:
            continue
    return False


def validate_request(run_id, timeout):
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}", run_id):
        raise DhcpError("invalid DHCP run_id")
    if isinstance(timeout, bool) or not isinstance(timeout, int) or not 1 <= timeout <= 60:
        raise DhcpError("DHCP timeout must be 1-60 seconds")
    if not backend()["available"]:
        raise DhcpError("managed ISC dhclient backend or approved hook is unavailable")


def start(interface, run_id, gadget_name, serial_number, timeout=30):
    if os.geteuid() != 0:
        raise DhcpError("DHCP operations require the root-running MCP service")
    directory = _directory(interface)
    validate_request(run_id, timeout)
    previous = status(interface)
    if previous["pid"] or previous["status"] == "cleanup_required":
        if previous["run_id"] != run_id or previous["gadget_name"] != gadget_name or previous["serial_number"] != serial_number:
            raise DhcpError("another run owns this interface's DHCP session")
        return previous
    if _external_clients(interface):
        raise DhcpError("an unmanaged DHCP client already owns this USB interface")
    if any(not ipaddress.IPv4Interface(address).ip.is_link_local for address in _cidrs(interface)):
        raise DhcpError("USB interface already has an unowned IPv4 address; refusing to replace it")
    _secure_directory(ROOT)
    _secure_directory(directory)
    index = _ifindex(interface)
    if index is None:
        raise DhcpError("USB interface is absent")
    # Runtime-only ownership of this USB interface; no eth0/wlan0 profile changes.
    if shutil.which("nmcli"):
        _run(["nmcli", "device", "set", interface, "managed", "no"])
    _run(["ip", "link", "set", "dev", interface, "up"])
    meta = {"interface": interface, "ifindex": index, "run_id": run_id,
            "gadget_name": gadget_name, "serial_number": serial_number,
            "token": uuid.uuid4().hex, "active": True}
    _write(directory / "session.json", meta)
    _write(directory / "lease.json", {})
    (directory / "client.conf").write_text("timeout %d;\nretry 5;\ninitial-interval 1;\n" % timeout)
    (directory / "client.leases").write_text("")
    with (directory / "client.log").open("wb") as log:
        process = subprocess.Popen(_command(meta), stdout=log, stderr=log, start_new_session=True)
    meta["pid"] = process.pid
    _write(directory / "session.json", meta)
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        result = status(interface)
        if result["status"] == "bound":
            return result
        if result["status"] == "failed" or process.poll() is not None:
            break
        time.sleep(0.2)
    evidence = status(interface)
    stop(interface, run_id)
    raise DhcpError("DHCP lease acquisition failed: " + (evidence["lease"].get("error") or evidence["log_tail"][-1200:] or "timeout"))


def apply_hook(directory, token, environment):
    directory = Path(directory)
    if directory.parent != ROOT or not re.fullmatch(r"usb[0-9]+", directory.name):
        raise DhcpError("invalid DHCP hook state path")
    _secure_directory(ROOT)
    _secure_directory(directory)
    meta, lease = _read(directory / "session.json"), _read(directory / "lease.json")
    interface, reason = environment.get("interface"), environment.get("reason", "")
    if meta.get("token") != token or interface != meta.get("interface"):
        raise DhcpError("DHCP hook does not own this session")
    if reason in {"BOUND", "RENEW", "REBIND", "REBOOT"}:
        if not meta.get("active") or _ifindex(interface) != meta.get("ifindex"):
            raise DhcpError("DHCP hook interface instance changed")
        address = ipaddress.IPv4Interface("%s/%s" % (environment["new_ip_address"], environment["new_subnet_mask"]))
        # OEM USBLAN DHCP servers intentionally use narrow 169.254 subnets.
        # A /16 still denotes automatic APIPA, not an explicit test lease.
        automatic_link_local = address.ip.is_link_local and address.network.prefixlen <= 16
        if address.network.prefixlen == 0 or address.ip.is_multicast or address.ip.is_loopback or address.ip.is_unspecified or automatic_link_local:
            raise DhcpError("unsafe DHCP address or mask")
        if address.network.prefixlen < 31 and address.ip in (address.network.network_address, address.network.broadcast_address):
            raise DhcpError("DHCP offered a network or broadcast address")
        for row in _addresses():
            if row["ifname"] == interface or row["ifname"] == "lo":
                continue
            for ip in row.get("addr_info", []):
                if ip.get("family") == "inet" and address.network.overlaps(ipaddress.IPv4Interface("%s/%s" % (ip["local"], ip["prefixlen"])).network):
                    raise DhcpError("DHCP subnet overlaps another host interface")
        if lease.get("address") and lease["address"] != str(address):
            _remove_address(meta, lease)
        _run(["ip", "address", "replace", str(address), "dev", interface])
        lease.update(address=str(address), options={key[4:]: value for key, value in environment.items() if key.startswith("new_")})
    elif reason in {"EXPIRE", "FAIL", "STOP", "RELEASE"}:
        _remove_address(meta, lease)
    elif reason == "TIMEOUT":
        raise DhcpError("cached lease fallback is not permitted")
    # PREINIT/TIMEOUT never apply cached leases or flush existing addresses.
    lease.update(reason=reason, error=None, updated_at=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))
    _write(directory / "lease.json", lease)
    return lease


def hook_main():
    directory = Path(os.environ.get("PIGADGET_DHCP_DIR", ""))
    try:
        if os.geteuid() != 0:
            raise DhcpError("DHCP hook requires root")
        apply_hook(directory, os.environ.get("PIGADGET_DHCP_TOKEN"), os.environ)
    except Exception as exc:
        print(str(exc), file=sys.stderr)
        if (directory.parent == ROOT and re.fullmatch(r"usb[0-9]+", directory.name) and directory.is_dir()
                and _read(directory / "session.json").get("token") == os.environ.get("PIGADGET_DHCP_TOKEN")):
            lease = _read(directory / "lease.json")
            lease.update(error=str(exc), reason="ERROR")
            _write(directory / "lease.json", lease)
        sys.exit(1)
