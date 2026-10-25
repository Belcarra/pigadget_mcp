# pigadget_mcp

## Requirements

**gadgetconfig must be installed on the same Pi before installing and starting
pigadget-mcp.** Get it from [Belcarra/gadgetconfig](https://github.com/Belcarra/gadgetconfig)
and follow that repository's installation and USB gadget setup instructions.
For a source checkout:

```bash
git clone https://github.com/Belcarra/gadgetconfig.git
```

The Pi needs a gadget-capable USB controller, `libcomposite`, ConfigFS and an
available UDC. A desktop and `gadgetapp` are not required.

This service calls the installed `gadgetconfig` executable for gadget creation,
removal, enable/disable and soft connection; it does not replace gadgetconfig
or use it as an imported Python library. Installing pigadget-mcp does not
automatically install gadgetconfig. Verify the prerequisite before proceeding:

```bash
command -v gadgetconfig
sudo gadgetconfig --version
```

The executable must also be accessible to the service account. For a custom
installation path, set `PIGADGET_MCP_GADGETCONFIG=/absolute/path/to/gadgetconfig`
in `/etc/pigadget-mcp.env`, which the supplied systemd unit reads. The service
also reads ConfigFS/sysfs directly to verify actual gadget state and identity.

## Managed USB DHCP (0.6.0)

`gadget.configure_protocol` accepts `ipv4: "dhcp"` (alias `"dhcpc"`), an optional
`run_id`, and `dhcp_timeout` of 1-60 seconds. This acquires a real lease before
returning; no static or cached-lease fallback is used. A configuration failure
cleans up and restores the idle probe. Static address/prefix requests still work.

For separate addressing after gadget configuration, use:

- `network.dhcp_start(run_id, interface=None, timeout=30)`
- `network.dhcp_status(interface=None)`
- `network.dhcp_stop(interface, run_id=None)`

Start discovers the enabled gadget's actual `usbN` from ConfigFS, never assumes
usb0, and refuses the idle probe, other interfaces, competing clients, and
unowned IPv4 addresses. It takes runtime NetworkManager ownership away from
only that USB interface; it stays unmanaged until recreated. Management
interfaces/profiles are unchanged. The declared backend is ISC `dhclient` on
every lab Pi, using a package-installed, controlled hook and root-only state.
`deploy/install_wheel.sh` also installs the packaged NetworkManager policy
`service/pigadget-mcp-networkmanager.conf`: only `usb*` interfaces are unmanaged,
preventing automatic connection profiles from racing the MCP DHCP client.
It reloads configuration without restarting NetworkManager; deploy only when
the host is idle. Fresh installs using another procedure must install this file
as `/etc/NetworkManager/conf.d/90-pigadget-mcp-usb.conf` and run
`sudo nmcli general reload conf` before testing.

Responses include Pi serial, gadget/run identity, owned PID, leased address and
prefix, offered DHCP options (including server/lease information), and bounded
logs. The hook applies only the offered USB address: DNS and default-router
options are retained as evidence, not installed. Subnets overlapping another
host interface are refused. This is address acquisition/renewal testing, not
validation of every advertised DHCP option.
Version 0.6.1 accepts intentionally leased link-local subnets such as
`169.254.1.2/29`. Automatic APIPA `/16` remains rejected, as do overlapping
management networks. Run the isolated handshake test with `--link-local`
to exercise this OEM-kit addressing without changing a physical gadget.

Disable/unload releases managed DHCP first and removes only its owned address.
The lease client stays running for renewal during long tests. Sessions live
under `/run/pigadget-mcp/dhcp`; separate runs cannot replace an active session.

`deploy/sudoers-lab` deliberately grants `sl` and `codex` unrestricted passwordless
sudo to match the existing private lab policy. It is not an end-user deployment
policy. `deploy/bootstrap_lab.sh` validates it with visudo and installs
`isc-dhcp-client` if missing. MCP DHCP operations themselves run through the
root systemd service and do not require agent-side sudo.

Run unit tests with `python3 -m unittest discover -s tests` in an environment
with the package dependencies installed. The explicit root-only
`tests/dhcp_namespace_smoke.py` checks a real DHCP handshake and cleanup using
temporary veth interfaces and a network namespace; it requires dnsmasq, never
configures a physical gadget, and checks management routes/DNS are unchanged.

## Routine Network Setup

Use `gadget.configure_protocol` for standalone kit acceptance and customer-kit
load tests; no synchronized `/etc/gadgetservice` files are required:

```json
{
  "protocol": "eem",
  "vid": "1777",
  "pid": "0002",
  "ipv4": "192.168.188.2/24"
}
```

Protocols are `eem`, `ecm`, `rndis`, and `ncm` (case-insensitive). The service
generates one configuration with one network function using gadgetconfig's
existing definition schema; it does not add composite functions or Microsoft
OS descriptors. VID/PID require four hex digits, with an optional `0x` prefix.
The default gadget name is `mcp_test`. Optional parameters are `name`,
`serial_number`, `manufacturer`, `product`, `qmult`, `dev_addr`, and `host_addr`.
The Pi's stable serial and deterministic, distinct MAC addresses are defaults.
Omitting `ipv4` leaves address management to the existing network service.

Inventory advertises kernel module availability under `capabilities.protocols`.
The server validates input, kernel support, UDC, and idle state before removing
the probe. It refuses an active/soft-disconnected test or an existing gadget
with the requested name. Unload before switching tests. It identifies the
interface through that function's ConfigFS `ifname`, not an unrelated `usb0`.
Results include actual descriptors/serial, generated definition, interface,
command evidence, and status. An enabled gadget is not proof of Windows
enumeration: compare its serial with Windows before running traffic.

Setup failures remove the partial test and schedule the idle probe after five
seconds when idle mode is enabled. Cleanup failures are explicit errors needing
inspection, not successful restores. Call `gadget.unload` after testing.

## Testing Levels

- **Kit acceptance:** exact OEM/end-user kit verification, supplied installer,
  USB enumeration/serial correlation, ping and small transfers, then cleanup.
- **Customer-kit load:** acceptance plus bounded ping/iperf/reconnect workloads.
- **Development validation:** targeted regressions, platform/protocol matrices,
  diagnostics, stress, and advanced descriptor/composite configurations.

Agents select plans/pass criteria and record kit/hash, service versions, hosts,
configuration, results, and cleanup. Passing acceptance does not imply load or
development validation passed. Advanced `gadget.configure_profile` and
`gadget.add_profile` remain available; they now use the same `commentjson`
parser as gadgetconfig, including `#` and `//` comments.

## Idle Survey Mode

Set `PIGADGET_MCP_SURVEY_IDLE=1` in `/etc/pigadget-mcp.env` (or start with
`--survey-idle`). The systemd unit reads that file. The default is off.
On boot the service enables `gadget_probe`; service restarts preserve an
existing test, including a soft-disconnected test. Beginning a test removes
the survey definition and cancels any pending restore. `gadget.unload`
disables/removes the test and schedules the survey five seconds after the
operation completes. `gadget.disable` also schedules restoration but retains
the test definition. Soft disconnect/reconnect does not end the test.

`gadget.inventory`, `gadget.status`, `gadget.enable`, and
`gadget.configure_profile` return `identity`, including `pi_name`,
`serial_number`, VID/PID and whether the gadget is enabled. The serial is read
back from configfs. The default is the Pi hardware serial (a stable host-derived
fallback is used if unavailable), shared by survey and test profiles.
Explicit `overrides.serialnumber` is respected by `configure_profile`;
`gadget.enable` accepts `serial_number` for an explicitly different value.
The agent must compare this serial against Windows enumeration before traffic.

Do not use direct `gadgetconfig` changes while a managed test/restore is active;
MCP mutations are serialized and coordinate the restore timer.

## Survey History

`gadget.record_host(windows_host, seen_at, instance_id)` records a confirmed
Windows enumeration from the lab survey. `gadget.status` returns `last_host`.
History survives service restarts in `/var/lib/pigadget-mcp/survey.json`;
override with `PIGADGET_MCP_SURVEY_STATE`. An older observation cannot replace
a newer one. This describes the last confirmed connection, not current wiring.

For background surveys, `gadget.probe_enable(require_idle=True)` refuses to
replace a configured gadget, and `gadget.probe_disable(only_probe=True)` refuses
to disable a different gadget. Run focused tests with
`PYTHONPATH=. python3 -m unittest discover -s tests`.

`pigadget_mcp` is a small systemd MCP service for Raspberry Pi USB gadget test systems.
It exposes a typed subset of `gadgetconfig` operations so your MCP broker
server or MCP client can discover and call Pi gadget capabilities.

It is a separate service project. Install `gadgetconfig` first on the Pi; this
package shells out to the installed `gadgetconfig` command and does not replace
it.

## Tools

- `gadget.inventory`
- `gadget.status`
- `gadget.add_profile`
- `gadget.enable`
- `gadget.disable`
- `gadget.unload`
- `gadget.soft_connect`
- `gadget.soft_disconnect`
- `gadget.configure_profile`
- `gadget.configure_protocol`
- `gadget.probe_enable`
- `gadget.probe_disable`
- `gadget.record_host`
- `gadget.collect_logs`

`gadget.inventory` reports separate package and capability metadata:

- app version: installed `pigadget-mcp` package version
- capability schema version: inventory/capability document format
- toolset version: MCP tool and argument/result contract version
- dependency version: installed `gadgetconfig` command version
- host capability class: coarse Pi class such as `pi5`, `pi4-limited`, or
  `pizero-control`

## Install

Install and verify [gadgetconfig](https://github.com/Belcarra/gadgetconfig)
first, as described under [Requirements](#requirements). Then, from the
pigadget_mcp source directory on the Pi:

```bash
make install
```

That does two things:

1. installs the Python package
2. installs, enables, and starts the `pigadget-mcp.service` systemd unit

If the Pi needs `--break-system-packages`:

```bash
make install_with_break
```

## Default Service Address

The systemd service listens on:

- `0.0.0.0:8000`

For local source-tree testing:

```bash
PYTHONPATH=. PIGADGET_MCP_GADGETCONFIG=/usr/local/bin/gadgetconfig \
  python3 -m pigadget_mcp.server --json-inventory
```

## Notes

- The service runs as root because `gadgetconfig` mutates ConfigFS and UDC state.
- Profile paths are restricted to approved directories. Override with
  `PIGADGET_MCP_PROFILE_DIRS=/etc/gadgetservice:/path/to/definitions`.
- The supplied HTTP service has no configured authentication or TLS and listens
  on all interfaces. Anyone who can reach it can invoke its privileged tools.
  Restrict access with a firewall, private network/VPN, or authenticated proxy;
  do not expose it directly to the internet. Broker authentication alone does
  not protect direct access to the Pi endpoint.
- `deploy/bootstrap_lab.sh` and `deploy/sudoers-lab` are optional private-lab
  helpers, not prerequisites for MCP operation. Do not apply their unrestricted
  passwordless-sudo policy to a general-purpose installation.

## Lab Survey Probe

`gadget.probe_enable` writes `/etc/gadgetservice/gadget_probe.json`, disables any
current gadget, removes an old `gadget_probe` definition, adds the generated
profile, and enables it. The generated probe uses VID `15ec` and a Pi-specific
PID so Windows hosts can identify which Pi is physically connected:

```text
pi1=a001  pi2=a002  pi3=a003  pi5=a005
pz1=a011  pz2=a012  pz3=a013
```

Use `function="eem"` by default, or `function="ecm"` when a host should see an
ECM probe. `gadget.probe_disable` disables the active gadget and removes the
temporary definition by default.
