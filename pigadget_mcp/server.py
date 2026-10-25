#!/usr/bin/python3
# -*- coding: utf-8 -*-

"""MCP tools for the existing gadgetconfig command line interface."""

import argparse
import ast
import hashlib
import ipaddress
import glob
import json
import os
import re
import socket
import subprocess
import sys
import threading
import tempfile
import time
import uuid
from functools import wraps
from datetime import datetime, timezone
from pathlib import Path

from pigadget_mcp.version import VERSION as APP_VERSION
from pigadget_mcp import dhcp


DEFAULT_TIMEOUT = int(os.environ.get("PIGADGET_MCP_TIMEOUT", "20"))
GADGETCONFIG_BIN = os.environ.get("PIGADGET_MCP_GADGETCONFIG", "gadgetconfig")
CAPABILITY_SCHEMA_VERSION = 1
TOOLSET_VERSION = "0.6"
TOOL_NAMES = [
    "gadget.inventory",
    "gadget.status",
    "gadget.add_profile",
    "gadget.enable",
    "gadget.disable",
    "gadget.unload",
    "gadget.soft_connect",
    "gadget.soft_disconnect",
    "gadget.configure_profile",
    "gadget.configure_protocol",
    "gadget.probe_enable",
    "gadget.probe_disable",
    "gadget.record_host",
    "gadget.collect_logs",
    "network.dhcp_start",
    "network.dhcp_status",
    "network.dhcp_stop",
]
PROBE_NAME = "gadget_probe"
PROBE_PROFILE_PATH = Path("/etc/gadgetservice/gadget_probe.json")
SURVEY_STATE_PATH = Path(os.environ.get("PIGADGET_MCP_SURVEY_STATE", "/var/lib/pigadget-mcp/survey.json"))
SURVEY_LOCK = threading.Lock()
GADGET_ROOT = Path(os.environ.get("PIGADGET_MCP_CONFIGFS", "/sys/kernel/config/usb_gadget"))
UDC_ROOT = Path("/sys/class/udc")
GADGET_LOCK = threading.RLock()
IDLE_SURVEY_ENABLED = os.environ.get("PIGADGET_MCP_SURVEY_IDLE", "0").lower() in {"1", "true", "yes"}
RESTORE_DELAY = 5.0
RESTORE_TIMER = None
RESTORE_GENERATION = 0
TEST_GADGET = None
IDLE_ERROR = None
PROBE_PID_MAP = {
    "pi1": "0xa001",
    "pi2": "0xa002",
    "pi3": "0xa003",
    "pi5": "0xa005",
    "pz1": "0xa011",
    "pz2": "0xa012",
    "pz3": "0xa013",
}
DEFAULT_PROFILE_DIRS = [
    "/etc/gadgetservice",
    "/usr/local/share/gadgetconfig/definitions",
    "/usr/share/gadgetconfig/definitions",
]


class GadgetError(Exception):
    """Raised for validation errors before a command is run."""


def _survey_state():
    try:
        data = json.loads(SURVEY_STATE_PATH.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except FileNotFoundError:
        return {}


def _update_survey_state(**values):
    with SURVEY_LOCK:
        state = _survey_state()
        state.update(values)
        SURVEY_STATE_PATH.parent.mkdir(parents=True, exist_ok=True)
        temporary = SURVEY_STATE_PATH.with_suffix(".tmp")
        temporary.write_text(json.dumps(state, indent=2) + "\n", encoding="utf-8")
        temporary.replace(SURVEY_STATE_PATH)


def _serialized(function):
    @wraps(function)
    def wrapped(*args, **kwargs):
        with GADGET_LOCK:
            return function(*args, **kwargs)
    return wrapped


def _default_serial_number():
    serial = _read_text("/proc/device-tree/serial-number")
    if serial:
        return serial.replace("\x00", "").strip()
    machine = _read_text("/etc/machine-id") or socket.gethostname()
    return "%s-%s" % (socket.gethostname().split(".")[0], hashlib.sha256(machine.encode()).hexdigest()[:12])


def _current_name():
    for path in GADGET_ROOT.glob("*/UDC"):
        if _read_text(path):
            return path.parent.name
    return None


def _gadget_path(name):
    if not name or name in (".", "..") or Path(name).name != name:
        raise GadgetError("invalid gadget name")
    return GADGET_ROOT / name


def _identity(name=None):
    current = _current_name()
    selected = name or current or TEST_GADGET
    path = _gadget_path(selected) if selected else None
    strings = sorted(path.glob("strings/*/serialnumber")) if path else []
    return {
        "pi_name": socket.gethostname().split(".")[0].lower(),
        "default_serial_number": _default_serial_number(),
        "gadget_name": selected,
        "serial_number": _read_text(strings[0]) if strings else None,
        "vid": _read_text(path / "idVendor") if path else None,
        "pid": _read_text(path / "idProduct") if path else None,
        "enabled": bool(selected and selected == current),
    }


def _set_serial_number(name, serial):
    if not serial or not re.fullmatch(r"[A-Za-z0-9_.-]{1,126}", serial):
        raise GadgetError("serial number must contain 1-126 letters, digits, dots, underscores or hyphens")
    paths = list(_gadget_path(name).glob("strings/*/serialnumber"))
    if not paths:
        raise GadgetError("gadget has no serial descriptor: %s" % name)
    for path in paths:
        path.write_text(serial, encoding="ascii")


def _cancel_restore():
    global RESTORE_TIMER, RESTORE_GENERATION
    RESTORE_GENERATION += 1
    if RESTORE_TIMER:
        RESTORE_TIMER.cancel()
        RESTORE_TIMER = None


def _claim_test(name):
    global TEST_GADGET
    TEST_GADGET = name
    if IDLE_SURVEY_ENABLED:
        _update_survey_state(test_gadget=name)


def _prepare_test(name):
    _cancel_restore()
    dhcp.stop_gadget(TEST_GADGET)
    if _current_name() == PROBE_NAME or _gadget_path(PROBE_NAME).exists():
        if _current_name() == PROBE_NAME:
            _checked_config(["--disable"])
        _checked_config(["--remove", PROBE_NAME])
    _claim_test(name)


def _checked_config(args):
    result = _gadgetconfig(args)
    if not result["ok"]:
        raise GadgetError(result["stderr"] or "gadgetconfig failed: %s" % args)
    return result


def _restore_survey(generation):
    global RESTORE_TIMER, IDLE_ERROR
    with GADGET_LOCK:
        if generation != RESTORE_GENERATION or not IDLE_SURVEY_ENABLED or TEST_GADGET:
            return
        RESTORE_TIMER = None
        try:
            current = _current_name()
            if current and current != PROBE_NAME:
                return
            result = gadget_probe_enable(require_idle=False)
            if not result["add"]["ok"] or not result["enable"]["ok"]:
                raise GadgetError("failed to enable idle survey gadget")
            IDLE_ERROR = None
        except Exception as exc:
            IDLE_ERROR = str(exc)
            print("idle survey: %s" % exc, file=sys.stderr)


def _schedule_restore(delay=RESTORE_DELAY):
    global RESTORE_TIMER
    _cancel_restore()
    if not IDLE_SURVEY_ENABLED:
        return None
    RESTORE_TIMER = threading.Timer(delay, _restore_survey, args=(RESTORE_GENERATION,))
    RESTORE_TIMER.daemon = True
    RESTORE_TIMER.start()
    return delay


@_serialized
def _initialize_idle_survey():
    if not IDLE_SURVEY_ENABLED:
        return
    current = _current_name()
    state = _survey_state()
    boot_id = _read_text("/proc/sys/kernel/random/boot_id")
    new_boot = bool(state.get("boot_id") and state["boot_id"] != boot_id)
    _update_survey_state(boot_id=boot_id)
    saved = state.get("test_gadget")
    if new_boot:
        _checked_config(["--disable"])
        _claim_test(None)
        _schedule_restore(0)
        return
    if current and current != PROBE_NAME:
        _claim_test(current)
    elif saved and _gadget_path(saved).exists():
        _claim_test(saved)
    else:
        _claim_test(None)
        _schedule_restore(0)


def gadget_record_host(windows_host: str, seen_at: str, instance_id: str = ""):
    """Persist a host confirmed by an external USB survey; this is historical evidence."""
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,252}", windows_host):
        raise GadgetError("invalid Windows hostname")
    observed = datetime.fromisoformat(seen_at.replace("Z", "+00:00"))
    if observed.tzinfo is None:
        raise GadgetError("seen_at must be a timezone-aware timestamp")
    record = {"windows_host": windows_host, "seen_at": observed.astimezone(timezone.utc).isoformat().replace("+00:00", "Z"), "instance_id": instance_id}
    with SURVEY_LOCK:
        previous = _survey_state().get("last_host")
        if previous and datetime.fromisoformat(previous["seen_at"].replace("Z", "+00:00")) > observed:
            return {"last_host": previous}
        SURVEY_STATE_PATH.parent.mkdir(parents=True, exist_ok=True)
        temporary = SURVEY_STATE_PATH.with_suffix(".tmp")
        state = _survey_state()
        state["last_host"] = record
        temporary.write_text(json.dumps(state, indent=2) + "\n", encoding="utf-8")
        temporary.replace(SURVEY_STATE_PATH)
    return {"last_host": record}


def _allowed_profile_dirs():
    value = os.environ.get("PIGADGET_MCP_PROFILE_DIRS")
    if value:
        return [Path(p).resolve() for p in value.split(":") if p]
    return [Path(p).resolve() for p in DEFAULT_PROFILE_DIRS]


def _run(argv, timeout=DEFAULT_TIMEOUT):
    try:
        completed = subprocess.run(
            argv,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            universal_newlines=True,
            timeout=timeout,
            check=False,
        )
        return {
            "argv": argv,
            "returncode": completed.returncode,
            "stdout": completed.stdout,
            "stderr": completed.stderr,
            "ok": completed.returncode == 0,
        }
    except FileNotFoundError:
        return {
            "argv": argv,
            "returncode": 127,
            "stdout": "",
            "stderr": "command not found: %s" % argv[0],
            "ok": False,
        }
    except subprocess.TimeoutExpired as exc:
        return {
            "argv": argv,
            "returncode": 124,
            "stdout": exc.stdout or "",
            "stderr": exc.stderr or "command timed out",
            "ok": False,
        }


def _gadgetconfig(args):
    return _run([GADGETCONFIG_BIN] + list(args))


def _parse_suffix(output, prefix):
    for line in output.splitlines():
        line = line.strip()
        if line.startswith(prefix):
            return line[len(prefix):].strip()
    return None


def _parse_list(value):
    if not value:
        return []
    try:
        parsed = ast.literal_eval(value)
        if isinstance(parsed, list):
            return parsed
    except (SyntaxError, ValueError):
        pass
    return [value]


def _query():
    queries = {
        "current": _gadgetconfig(["--query-gadget"]),
        "defined": _gadgetconfig(["--query-gadgets"]),
        "functions": _gadgetconfig(["--query-gadget-functions"]),
        "udc": _gadgetconfig(["--query-udc"]),
    }


    current_text = queries["current"]["stderr"] + queries["current"]["stdout"]
    defined_text = queries["defined"]["stderr"] + queries["defined"]["stdout"]
    functions_text = queries["functions"]["stderr"] + queries["functions"]["stdout"]
    udc_text = queries["udc"]["stderr"] + queries["udc"]["stdout"]
    return {
        "current_gadget": _parse_suffix(current_text, "Currently configured:"),
        "defined_gadgets": _parse_list(_parse_suffix(defined_text, "Currently defined gadgets:")),
        "active_functions": _parse_list(_parse_suffix(functions_text, "UDC Function:")),
        "udc_state": _parse_suffix(udc_text, "UDC State:"),
        "udc_function": _parse_suffix(udc_text, "UDC Function:"),
        "commands": queries,
    }


def _configfs_query():
    current = _current_name()
    controllers = sorted(UDC_ROOT.glob("*"))
    controller = controllers[0] if controllers else None
    return {
        "current_gadget": current or "GADGET NOT CONFIGURED",
        "defined_gadgets": sorted(path.name for path in GADGET_ROOT.iterdir() if path.is_dir()) if GADGET_ROOT.is_dir() else [],
        "active_functions": sorted(path.name for path in (GADGET_ROOT / current / "functions").glob("*")) if current else ["NO GADGET"],
        "udc_state": _read_text(controller / "state") if controller else None,
        "udc_function": _read_text(controller / "function") if controller else None,
        "commands": {},
    }


def _read_text(path):
    try:
        with open(path, "r") as fh:
            return fh.read().strip()
    except (OSError, UnicodeDecodeError):
        return None


def _qmult_values():
    values = {}
    for path in glob.glob("/sys/kernel/config/usb_gadget/*/functions/*/qmult"):
        values[path] = _read_text(path)
    return values


def _usb_interfaces():
    result = _run(["ip", "-brief", "addr", "show"])
    interfaces = []
    for line in result["stdout"].splitlines():
        parts = line.split()
        if not parts:
            continue
        name = parts[0]
        if not re.match(r"^usb[0-9]+$", name):
            continue
        interfaces.append({
            "name": name,
            "state": parts[1] if len(parts) > 1 else "",
            "addresses": parts[2:] if len(parts) > 2 else [],
            "raw": line,
        })
    return {"interfaces": interfaces, "command": result}


def _kernel_log_tail(lines=80):
    result = _run(["dmesg", "--color=never"], timeout=10)
    if result["stdout"]:
        result["stdout"] = "\n".join(result["stdout"].splitlines()[-int(lines):])
    return result


def _proc_arp():
    return _read_text("/proc/net/arp") or ""


def _host_model():
    model = _read_text("/proc/device-tree/model")
    if model:
        return model.replace("\x00", "").strip()
    return _read_text("/sys/firmware/devicetree/base/model") or ""


def _mem_total_kb():
    meminfo = _read_text("/proc/meminfo") or ""
    for line in meminfo.splitlines():
        if line.startswith("MemTotal:"):
            parts = line.split()
            if len(parts) >= 2:
                try:
                    return int(parts[1])
                except ValueError:
                    return None
    return None


def _host_capability_class(model):
    lower = model.lower()
    if "raspberry pi 5" in lower:
        return "pi5"
    if "raspberry pi 4" in lower:
        return "pi4-limited"
    if "zero" in lower:
        return "pizero-control"
    if "raspberry pi" in lower:
        return "pi-gadget"
    return "unknown"


def _host_facts():
    model = _host_model()
    uname = _run(["uname", "-srm"])
    return {
        "hostname": socket.gethostname(),
        "model": model,
        "capability_class": _host_capability_class(model),
        "memory_kb": _mem_total_kb(),
        "kernel": uname["stdout"].strip(),
        "architecture": _run(["uname", "-m"])["stdout"].strip(),
    }


def _capability_document(gadgetconfig_version):
    return {
        "schema_version": CAPABILITY_SCHEMA_VERSION,
        "toolset_version": TOOLSET_VERSION,
        "tools": TOOL_NAMES,
        "dependencies": {
            "gadgetconfig": {
                "version": gadgetconfig_version,
                "command": GADGETCONFIG_BIN,
            },
        },
        "profile_dirs": [str(p) for p in _allowed_profile_dirs()],
        "protocols": _protocol_support(),
    }


def _resolve_profile(profile):
    path = Path(profile)
    candidates = []
    if path.is_absolute():
        candidates.append(path)
    else:
        for directory in _allowed_profile_dirs():
            candidates.append(directory / profile)
            if not profile.endswith(".json"):
                candidates.append(directory / ("%s.json" % profile))

    allowed = _allowed_profile_dirs()
    for candidate in candidates:
        resolved = candidate.resolve()
        if not resolved.is_file():
            continue
        if any(str(resolved).startswith(str(directory) + os.sep) or resolved == directory for directory in allowed):
            return str(resolved)
    raise GadgetError("profile is not in an approved directory or does not exist: %s" % profile)


def _load_profile(path):
    # Use the same parser as gadgetconfig, including # and // comments.
    try:
        import commentjson
    except ImportError as exc:
        raise GadgetError("install python3-commentjson in the service Python environment") from exc
    try:
        data = commentjson.loads(Path(path).read_text(encoding="utf-8"))
    except Exception as exc:
        raise GadgetError("invalid gadget profile: %s" % exc) from exc
    if not isinstance(data, dict) or not data or not all(isinstance(value, dict) for value in data.values()):
        raise GadgetError("profile must contain named gadget definitions")
    for name in data:
        _gadget_path(name)
    return data


def _protocol_support():
    support = {}
    for protocol in ("eem", "ecm", "rndis", "ncm"):
        result = _run(["/sbin/modprobe", "--dry-run", "usb_f_" + protocol])
        support[protocol] = {"available": result["ok"], "error": result["stderr"] if not result["ok"] else None}
    return support


def _override_args(overrides):
    args = []
    allowed = [
        "idVendor",
        "idProduct",
        "manufacturer",
        "product",
        "serialnumber",
        "dev_addr",
        "host_addr",
        "qmult",
        "name",
    ]
    for key in allowed:
        value = overrides.get(key)
        if value is not None:
            args.extend(["--%s" % key, str(value)])
    if overrides.get("auto_serialnumber"):
        args.append("--auto_serialnumber")
    return args


def _select_usb_interface(interfaces):
    current = _current_name()
    if current:
        for path in (GADGET_ROOT / current / "functions").glob("*/ifname"):
            name = _read_text(path)
            if name and any(interface["name"] == name for interface in interfaces):
                return name
    if not interfaces:
        return None
    for iface in interfaces:
        if iface.get("state") == "UP":
            return iface["name"]
    for iface in interfaces:
        if "LOWER_UP" in iface.get("raw", ""):
            return iface["name"]
    return interfaces[0]["name"]


def _configure_static_ip(interface, address):
    if not re.match(r"^usb[0-9]+$", interface):
        raise GadgetError("refusing to configure non-usb interface: %s" % interface)
    return [
        _run(["ip", "addr", "flush", "dev", interface]),
        _run(["ip", "addr", "add", address, "dev", interface]),
        _run(["ip", "link", "set", interface, "up"]),
    ]


def _normalize_hex16(value, field):
    text = str(value).strip().lower()
    if text.startswith("0x"):
        text = text[2:]
    if not re.fullmatch(r"[0-9a-f]{4}", text):
        raise GadgetError("%s must be four hex digits: %s" % (field, value))
    return "0x%s" % text


def _probe_pid_for(pi_name=None, pid=None):
    if pid is not None:
        return _normalize_hex16(pid, "pid")
    name = (pi_name or socket.gethostname()).split(".")[0].lower()
    mapped = PROBE_PID_MAP.get(name)
    if not mapped:
        raise GadgetError("no probe PID mapping for host %s; pass pid explicitly" % name)
    return mapped


def _mac_pair(seed):
    digest = hashlib.sha256(seed.encode("utf-8")).digest()
    dev = [0x02, digest[0], digest[1], digest[2], digest[3], digest[4]]
    host = [0x02, digest[5], digest[6], digest[7], digest[8], digest[9]]
    return (
        ":".join("%02x" % item for item in dev),
        ":".join("%02x" % item for item in host),
    )


def _probe_profile(pi_name, pid, serial, function):
    function = function.lower()
    if function not in {"eem", "ecm"}:
        raise GadgetError("probe function must be eem or ecm")
    function_name = "eem.usb0" if function == "eem" else "geth.usb0"
    dev_addr, host_addr = _mac_pair("%s-%s-%s" % (pi_name, pid, serial))
    return {
        PROBE_NAME: {
            "idVendor": "0x15ec",
            "idProduct": pid,
            "bcdDevice": "0x0001",
            "bDeviceClass": "0x00",
            "bDeviceSubClass": "0x00",
            "bDeviceProtocol": "0x00",
            "bcdUSB": "0x0200",
            "bMaxPacketSize0": "0x40",
            "strings": {
                "0x409": {
                    "serialnumber": serial,
                    "product": "Belcarra USBLAN Probe %s" % pi_name,
                    "manufacturer": "Belcarra",
                }
            },
            "functions": {
                function_name: {
                    "qmult": "5",
                    "host_addr": host_addr,
                    "dev_addr": dev_addr,
                }
            },
            "configs": {
                "Belcarra Probe.1": {
                    "bmAttributes": "0x80",
                    "MaxPower": "2",
                    "strings": {
                        "0x409": {
                            "configuration": "Belcarra USBLAN Probe %s" % function.upper(),
                        }
                    },
                    "functions": [
                        {
                            "name": function_name,
                            "function": function_name,
                        }
                    ],
                }
            },
        }
    }


def _write_probe_profile(profile):
    PROBE_PROFILE_PATH.parent.mkdir(parents=True, exist_ok=True)
    PROBE_PROFILE_PATH.write_text(json.dumps(profile, indent=4, sort_keys=True) + "\n", encoding="utf-8")
    return str(PROBE_PROFILE_PATH)


@_serialized
def gadget_inventory():
    """Return host, gadgetconfig, UDC, profile, and usb interface inventory."""
    query = _configfs_query()
    interfaces = _usb_interfaces()
    version = _gadgetconfig(["--version"])
    gadgetconfig_version = (version["stdout"] + version["stderr"]).strip()
    host = _host_facts()
    return {
        "identity": _identity(),
        "dhcp_backend": dhcp.backend(),
        "app": {
            "name": "pigadget-mcp",
            "version": APP_VERSION,
        },
        "capabilities": _capability_document(gadgetconfig_version),
        "host": host,
        "hostname": host["hostname"],
        "host_capability_class": host["capability_class"],
        "gadgetconfig_version": gadgetconfig_version,
        "profile_dirs": [str(p) for p in _allowed_profile_dirs()],
        "current_gadget": query["current_gadget"],
        "defined_gadgets": query["defined_gadgets"],
        "active_functions": query["active_functions"],
        "udc_state": query["udc_state"],
        "udc_function": query["udc_function"],
        "usb_interfaces": interfaces["interfaces"],
        "diagnostics": {
            "query_source": "configfs",
            "configfs_available": GADGET_ROOT.is_dir(),
            "version": version,
            "query": query["commands"],
            "ip": interfaces["command"],
        },
    }


@_serialized
def gadget_status(include_logs=False):
    """Return current gadget, UDC, qmult, interface, ARP, and optional logs."""
    query = _configfs_query()
    interfaces = _usb_interfaces()
    identity = _identity()
    status = {
        "identity": identity,
        "serial_number": identity.get("serial_number"),
        "dhcp": network_dhcp_status(),
        "idle_survey": {"enabled": IDLE_SURVEY_ENABLED, "restore_pending": RESTORE_TIMER is not None, "restore_delay_seconds": RESTORE_DELAY, "test_gadget": TEST_GADGET, "error": IDLE_ERROR},
        "last_host": _survey_state().get("last_host"),
        "current_gadget": query["current_gadget"],
        "defined_gadgets": query["defined_gadgets"],
        "active_functions": query["active_functions"],
        "udc_state": query["udc_state"],
        "udc_function": query["udc_function"],
        "qmult": _qmult_values(),
        "usb_interfaces": interfaces["interfaces"],
        "selected_usb_interface": _select_usb_interface(interfaces["interfaces"]),
        "arp": _proc_arp(),
        "diagnostics": {
            "query_source": "configfs",
            "configfs_available": GADGET_ROOT.is_dir(),
            "query": query["commands"],
            "ip": interfaces["command"],
        },
    }
    if include_logs:
        status["kernel_log_tail"] = _kernel_log_tail()
    return status


@_serialized
def gadget_add_profile(profile, overrides=None):
    """Add a gadget profile from an approved path or bundled definition."""
    overrides = dict(overrides or {})
    profile_path = _resolve_profile(profile)
    names = list(_load_profile(profile_path))
    if not names:
        raise GadgetError("profile contains no gadget definitions")
    if not overrides.get("serialnumber") and not overrides.get("auto_serialnumber"):
        overrides["serialnumber"] = _default_serial_number()
    _prepare_test(overrides.get("name") or names[0])
    return {
        "profile_path": profile_path,
        "gadget_names": names,
        "result": _gadgetconfig(["--add", profile_path] + _override_args(overrides)),
    }


@_serialized
def gadget_enable(name, serial_number=None):
    """Enable an already defined gadget."""
    _gadget_path(name)
    if name != PROBE_NAME:
        _prepare_test(name)
        _checked_config(["--disable"])
        _set_serial_number(name, serial_number or _default_serial_number())
    result = _gadgetconfig(["--enable", name])
    return {"result": result, "identity": _identity(name), "serial_number": _identity(name)["serial_number"], "status": gadget_status(False)}


@_serialized
def gadget_disable():
    """Disable the currently enabled gadget."""
    dhcp.stop_gadget(TEST_GADGET or _current_name())
    result = _gadgetconfig(["--disable"])
    if result["ok"]:
        _claim_test(None)
    response = {"result": result, "status": gadget_status(False)}
    response["survey_restore_in_seconds"] = _schedule_restore() if result["ok"] else None
    return response


@_serialized
def gadget_unload(name=None, remove=True):
    """Unload a test gadget and return to the idle survey after five seconds."""
    selected = name or TEST_GADGET or _current_name()
    if TEST_GADGET and selected != TEST_GADGET:
        raise GadgetError("another test gadget is loaded; refusing to unload it")
    if selected:
        _gadget_path(selected)
    current = _current_name()
    if current and selected and current != selected:
        raise GadgetError("another gadget is enabled; refusing to unload it")
    dhcp_cleanup = dhcp.stop_gadget(selected)
    disable = _checked_config(["--disable"])
    removed = _checked_config(["--remove", selected]) if remove and selected and _gadget_path(selected).exists() else None
    _claim_test(None)
    response = {"name": selected, "disable": disable, "remove": removed, "dhcp_cleanup": dhcp_cleanup, "status": gadget_status(False)}
    response["survey_restore_in_seconds"] = _schedule_restore()
    return response


@_serialized
def gadget_soft_connect():
    """Attach the configured UDC to the host."""
    return {"result": _gadgetconfig(["--soft-connect"]), "status": gadget_status(False)}


@_serialized
def gadget_soft_disconnect():
    """Detach the configured UDC from the host."""
    return {"result": _gadgetconfig(["--soft-disconnect"]), "status": gadget_status(False)}


@_serialized
def gadget_configure_profile(profile, name=None, static_ip=None, overrides=None):
    """Disable current gadget, add/reuse a profile, enable it, and rediscover usbN."""
    overrides = dict(overrides or {})
    if name is not None:
        overrides["name"] = name
    path = _resolve_profile(profile)
    names = list(_load_profile(path))
    enable_name = name or overrides.get("name") or (names[0] if len(names) == 1 else None)
    if not enable_name:
        raise GadgetError("specify name for a profile containing multiple gadgets")
    if len(names) > 1:
        if enable_name not in names:
            raise GadgetError("name must select an existing gadget in a multi-gadget profile")
        overrides.pop("name", None)
    _prepare_test(enable_name)
    disable_result = _checked_config(["--disable"])
    add_result = gadget_add_profile(profile, overrides=overrides)
    if not add_result["result"]["ok"]:
        raise GadgetError(add_result["result"]["stderr"] or "failed to add gadget")
    _claim_test(enable_name)
    enable_result = _gadgetconfig(["--enable", enable_name])
    status = gadget_status(False)
    ip_results = []
    if static_ip:
        iface = status["selected_usb_interface"]
        if not iface:
            raise GadgetError("cannot configure static IP; no usbN interface found")
        ip_results = _configure_static_ip(iface, static_ip)
        status = gadget_status(False)
    return {
        "identity": _identity(enable_name),
        "serial_number": _identity(enable_name)["serial_number"],
        "profile": add_result,
        "disable": disable_result,
        "enable": enable_result,
        "static_ip": ip_results,
        "status": status,
    }


@_serialized
def gadget_configure_protocol(protocol: str, vid: str, pid: str, ipv4: str = None,
                              name: str = "mcp_test", serial_number: str = None,
                              manufacturer: str = "Belcarra", product: str = None,
                              qmult: int = 5, dev_addr: str = None, host_addr: str = None,
                              run_id: str = None, dhcp_timeout: int = 30):
    """Configure one EEM/ECM/RNDIS/NCM function without a fleet profile file.

    Use for kit acceptance or customer-kit load tests. Unload an existing test
    first. Compare the returned serial with Windows USB enumeration before
    traffic. gadget.unload restores the idle survey; profiles remain available
    for advanced development configurations.
    """
    protocol = protocol.lower()
    if protocol not in {"eem", "ecm", "rndis", "ncm"}:
        raise GadgetError("protocol must be eem, ecm, rndis, or ncm")
    vid, pid = _normalize_hex16(vid, "vid"), _normalize_hex16(pid, "pid")
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}", name) or name == PROBE_NAME:
        raise GadgetError("invalid or reserved test gadget name")
    serial = serial_number if serial_number is not None else _default_serial_number()
    if not re.fullmatch(r"[A-Za-z0-9_.-]{1,126}", serial):
        raise GadgetError("invalid USB serial number")
    product = product if product is not None else "CDC " + protocol.upper()
    for value in (manufacturer, product):
        if not value or len(value.encode("utf-16-le")) > 252 or any(ord(char) < 32 for char in value):
            raise GadgetError("manufacturer/product must be nonempty USB strings without control characters")
    if isinstance(qmult, bool) or not isinstance(qmult, int) or not 1 <= qmult <= 100:
        raise GadgetError("qmult must be an integer from 1 to 100")
    use_dhcp = ipv4 in {"dhcp", "dhcpc"}
    if use_dhcp:
        run_id = run_id or "mcp-" + uuid.uuid4().hex
        try:
            dhcp.validate_request(run_id, dhcp_timeout)
        except dhcp.DhcpError as exc:
            raise GadgetError(str(exc)) from exc
    elif ipv4 is not None:
        try:
            if "/" not in ipv4:
                raise ValueError("prefix length required")
            ipv4 = str(ipaddress.IPv4Interface(ipv4))
        except ValueError as exc:
            raise GadgetError("ipv4 must be an IPv4 address/prefix") from exc
    default_dev, default_host = _mac_pair(_default_serial_number())
    dev_addr = dev_addr if dev_addr is not None else default_dev
    host_addr = host_addr if host_addr is not None else default_host
    for mac in (dev_addr, host_addr):
        if not re.fullmatch(r"(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}", mac) or int(mac[:2], 16) & 1 or int(mac.replace(":", ""), 16) == 0:
            raise GadgetError("MAC addresses must be nonzero unicast addresses")
    if dev_addr.lower() == host_addr.lower():
        raise GadgetError("device and host MAC addresses must differ")
    current = _current_name()
    if TEST_GADGET or (current and current != PROBE_NAME):
        raise GadgetError("a test gadget is already loaded; unload it before configuring another")
    if _gadget_path(name).exists():
        raise GadgetError("gadget name already exists; refusing to reuse stale descriptors")
    if not GADGET_ROOT.is_dir() or not any(UDC_ROOT.glob("*")):
        raise GadgetError("ConfigFS/UDC is unavailable")
    support = _protocol_support()[protocol]
    if not support["available"]:
        raise GadgetError("protocol unavailable on this kernel: %s: %s" % (protocol, support["error"]))

    function = protocol + ".usb0"
    definition = {name: {
        "idVendor": vid, "idProduct": pid, "bcdDevice": "0x0001",
        "bDeviceClass": "0x00", "bDeviceSubClass": "0x00", "bDeviceProtocol": "0x00",
        "bcdUSB": "0x0200", "bMaxPacketSize0": "0x40",
        "strings": {"0x409": {"serialnumber": serial, "manufacturer": manufacturer, "product": product}},
        "functions": {function: {"qmult": str(qmult), "dev_addr": dev_addr, "host_addr": host_addr}},
        "configs": {"c.1": {"bmAttributes": "0x80", "MaxPower": "2",
                              "strings": {"0x409": {"configuration": product}},
                              "functions": [{"name": function, "function": function}]}},
    }}
    try:
        _prepare_test(name)
        disable = _checked_config(["--disable"])
        with tempfile.TemporaryDirectory(prefix="pigadget-mcp-") as directory:
            path = Path(directory) / "definition.json"
            path.write_text(json.dumps(definition), encoding="utf-8")
            add = _checked_config(["--add", str(path)])
        enable = _checked_config(["--enable", name])
        if _current_name() != name:
            raise GadgetError("gadgetconfig reported success but the gadget is not bound")
        identity = _identity(name)
        if (identity["serial_number"] != serial or
                _normalize_hex16(identity["vid"], "actual vid") != vid or
                _normalize_hex16(identity["pid"], "actual pid") != pid):
            raise GadgetError("actual USB descriptors do not match the requested configuration")
        deadline = time.monotonic() + 5
        interface = None
        while time.monotonic() < deadline:
            interface = _read_text(_gadget_path(name) / "functions" / function / "ifname")
            if interface and any(item["name"] == interface for item in _usb_interfaces()["interfaces"]):
                break
            interface = None
            time.sleep(0.1)
        if not interface or not re.fullmatch(r"usb[0-9]+", interface):
            raise GadgetError("cannot identify this gadget's usbN interface")
        lease = dhcp.start(interface, run_id, name, identity["serial_number"], dhcp_timeout) if use_dhcp else None
        if lease is not None and lease.get("status") != "bound":
            raise GadgetError("DHCP session is not bound: %s" % lease.get("status"))
        ip_results = _configure_static_ip(interface, ipv4) if ipv4 and not use_dhcp else []
        if any(not result["ok"] for result in ip_results):
            raise GadgetError("static IPv4 configuration failed: " + "; ".join(result["stderr"] for result in ip_results if not result["ok"]))
        descriptors = {key: _read_text(_gadget_path(name) / key) for key in
                       ("idVendor", "idProduct", "bcdDevice", "bDeviceClass", "bDeviceSubClass", "bDeviceProtocol", "bcdUSB")}
        descriptors["strings"] = {key: _read_text(_gadget_path(name) / "strings/0x409" / key)
                                  for key in ("serialnumber", "manufacturer", "product")}
        return {"protocol": protocol, "identity": identity, "serial_number": identity["serial_number"],
                "descriptors": descriptors, "definition": definition, "usb_interface": interface,
                "disable": disable, "add": add, "enable": enable, "static_ip": ip_results, "dhcp": lease,
                "status": gadget_status(False)}
    except Exception as exc:
        try:
            dhcp.stop_gadget(name)
            _checked_config(["--disable"])
            if _gadget_path(name).exists():
                _checked_config(["--remove", name])
            _claim_test(None)
            delay = _schedule_restore()
        except Exception as cleanup_error:
            raise GadgetError("%s; cleanup failed: %s; inspect gadget.status before retrying" % (exc, cleanup_error)) from exc
        raise GadgetError("%s; test removed; idle survey restore in %s seconds" % (exc, delay)) from exc


@_serialized
def gadget_probe_enable(pi_name=None, pid=None, serial=None, function="eem", static_ip=None, require_idle=False):
    """Configure and enable the temporary lab survey gadget."""
    if require_idle:
        query = _query()
        if not query["commands"]["current"]["ok"] or query["current_gadget"] != "GADGET NOT CONFIGURED":
            raise GadgetError("survey requires an idle gadget host")
    pi = (pi_name or socket.gethostname()).split(".")[0].lower()
    probe_pid = _probe_pid_for(pi, pid)
    _cancel_restore()
    probe_serial = serial or _default_serial_number()
    profile = _probe_profile(pi, probe_pid, probe_serial, function)
    profile_path = _write_probe_profile(profile)
    disable = _gadgetconfig(["--disable"])
    remove = _gadgetconfig(["--remove", PROBE_NAME])
    add = _gadgetconfig(["--add", profile_path])
    enable = _gadgetconfig(["--enable", PROBE_NAME])
    status = gadget_status(False)
    if enable["ok"]:
        _claim_test(None)
    ip_results = []
    if static_ip:
        iface = status["selected_usb_interface"]
        if not iface:
            raise GadgetError("cannot configure static IP; no usbN interface found")
        ip_results = _configure_static_ip(iface, static_ip)
        status = gadget_status(False)
    return {
        "pi_name": pi,
        "vid": "0x15ec",
        "pid": probe_pid,
        "serialnumber": probe_serial,
        "serial_number": _identity(PROBE_NAME)["serial_number"],
        "identity": _identity(PROBE_NAME),
        "function": function.lower(),
        "profile_path": profile_path,
        "disable": disable,
        "remove": remove,
        "add": add,
        "enable": enable,
        "static_ip": ip_results,
        "status": status,
    }


@_serialized
def gadget_probe_disable(remove=True, only_probe=False):
    """Disable and optionally remove the temporary lab survey gadget."""
    if only_probe:
        query = _query()
        if not query["commands"]["current"]["ok"] or query["current_gadget"] not in (PROBE_NAME, "GADGET NOT CONFIGURED"):
            raise GadgetError("refusing to disable a non-probe gadget")
    disable = _gadgetconfig(["--disable"])
    remove_result = _gadgetconfig(["--remove", PROBE_NAME]) if remove else None
    response = {
        "name": PROBE_NAME,
        "profile_path": str(PROBE_PROFILE_PATH),
        "disable": disable,
        "remove": remove_result,
        "status": gadget_status(False),
    }
    response["survey_restore_in_seconds"] = _schedule_restore() if disable["ok"] else None
    return response


def gadget_collect_logs(lines=120):
    """Collect lightweight diagnostic evidence for a gadget test run."""
    return {
        "status": gadget_status(False),
        "kernel_log_tail": _kernel_log_tail(lines=lines),
    }


def _dhcp_interface(interface=None):
    current = _current_name()
    if not current or current == PROBE_NAME:
        raise GadgetError("DHCP requires an enabled test gadget, not the idle probe")
    names = {value for path in _gadget_path(current).glob("functions/*/ifname")
             for value in [_read_text(path)] if value and re.fullmatch(r"usb[0-9]+", value)}
    if interface is not None:
        if interface not in names:
            raise GadgetError("interface does not belong to the enabled gadget")
        return interface, current
    if len(names) != 1:
        raise GadgetError("specify the gadget's USB interface explicitly")
    return next(iter(names)), current


@_serialized
def network_dhcp_start(run_id: str, interface: str = None, timeout: int = 30):
    """Acquire and renew a USB-only DHCP lease; no DNS/default-route changes or static fallback."""
    interface, current = _dhcp_interface(interface)
    try:
        return dhcp.start(interface, run_id, current, _identity(current)["serial_number"], timeout)
    except dhcp.DhcpError as exc:
        return {"status": "not_ready", "reason": str(exc), "interface": interface,
                "run_id": run_id, "dhcp": dhcp.status(interface)}


@_serialized
def network_dhcp_status(interface: str = None):
    """Report backend, current lease/prefix, DHCP options, owned PID/run, and bounded logs."""
    try:
        sessions = [dhcp.status(interface)] if interface else [dhcp.status(path.name) for path in dhcp.ROOT.glob("usb*") if path.is_dir()]
        return {"backend": dhcp.backend(), "sessions": sessions}
    except dhcp.DhcpError as exc:
        raise GadgetError(str(exc)) from exc


@_serialized
def network_dhcp_stop(interface: str, run_id: str = None):
    """Release only this managed USB DHCP session and remove only its leased address."""
    try:
        return dhcp.stop(interface, run_id)
    except dhcp.DhcpError as exc:
        raise GadgetError(str(exc)) from exc


def _build_mcp(host, port, log_level):
    try:
        from mcp.server.fastmcp import FastMCP
    except ImportError:
        print("pigadget-mcp requires the 'mcp' Python package", file=sys.stderr)
        print("Install with: pip3 install pigadget-mcp", file=sys.stderr)
        raise

    mcp = FastMCP(
        "pigadget-mcp",
        instructions="Typed Raspberry Pi USB gadget tools backed by gadgetconfig.",
        host=host,
        port=port,
        log_level=log_level,
    )

    mcp.tool(name="gadget.inventory")(gadget_inventory)
    mcp.tool(name="gadget.status")(gadget_status)
    mcp.tool(name="gadget.add_profile")(gadget_add_profile)
    mcp.tool(name="gadget.enable")(gadget_enable)
    mcp.tool(name="gadget.disable")(gadget_disable)
    mcp.tool(name="gadget.unload")(gadget_unload)
    mcp.tool(name="gadget.soft_connect")(gadget_soft_connect)
    mcp.tool(name="gadget.soft_disconnect")(gadget_soft_disconnect)
    mcp.tool(name="gadget.configure_profile")(gadget_configure_profile)
    mcp.tool(name="gadget.configure_protocol")(gadget_configure_protocol)
    mcp.tool(name="gadget.probe_enable")(gadget_probe_enable)
    mcp.tool(name="gadget.probe_disable")(gadget_probe_disable)
    mcp.tool(name="gadget.record_host")(gadget_record_host)
    mcp.tool(name="gadget.collect_logs")(gadget_collect_logs)
    mcp.tool(name="network.dhcp_start")(network_dhcp_start)
    mcp.tool(name="network.dhcp_status")(network_dhcp_status)
    mcp.tool(name="network.dhcp_stop")(network_dhcp_stop)
    return mcp


def main():
    parser = argparse.ArgumentParser(description="MCP server for Raspberry Pi gadgetconfig")
    parser.add_argument("--transport", choices=["stdio", "sse", "streamable-http"], default="stdio")
    parser.add_argument("--host", default=os.environ.get("PIGADGET_MCP_HOST", "127.0.0.1"))
    parser.add_argument("--port", type=int, default=int(os.environ.get("PIGADGET_MCP_PORT", "8000")))
    parser.add_argument("--log-level", default=os.environ.get("PIGADGET_MCP_LOG_LEVEL", "INFO"))
    parser.add_argument("--json-status", action="store_true", help="print status JSON and exit")
    parser.add_argument("--survey-idle", action="store_true", help="Enable persistent survey when no test gadget is loaded")
    parser.add_argument("--json-inventory", action="store_true", help="print inventory JSON and exit")
    args = parser.parse_args()
    global IDLE_SURVEY_ENABLED
    IDLE_SURVEY_ENABLED = IDLE_SURVEY_ENABLED or args.survey_idle

    if args.json_inventory:
        print(json.dumps(gadget_inventory(), indent=2, sort_keys=True))
        return

    if args.json_status:
        print(json.dumps(gadget_status(include_logs=False), indent=2, sort_keys=True))
        return

    mcp = _build_mcp(args.host, args.port, args.log_level)
    _initialize_idle_survey()
    try:
        mcp.run(transport=args.transport)
    finally:
        with GADGET_LOCK:
            _cancel_restore()


if __name__ == "__main__":
    main()
