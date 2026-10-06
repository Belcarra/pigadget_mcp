# pigadget_mcp

`pigadget_mcp` is a small systemd MCP service for Raspberry Pi USB gadget test systems.
It exposes a typed subset of `gadgetconfig` operations so an MCP broker on
`whiskey` can discover and call Pi gadget capabilities.

It is a separate service project. Install `gadgetconfig` first on the Pi; this
package shells out to the installed `gadgetconfig` command and does not replace
it.

## Tools

- `gadget.inventory`
- `gadget.status`
- `gadget.add_profile`
- `gadget.enable`
- `gadget.disable`
- `gadget.soft_connect`
- `gadget.soft_disconnect`
- `gadget.configure_profile`
- `gadget.probe_enable`
- `gadget.probe_disable`
- `gadget.collect_logs`

`gadget.inventory` reports separate package and capability metadata:

- app version: installed `pigadget-mcp` package version
- capability schema version: inventory/capability document format
- toolset version: MCP tool and argument/result contract version
- dependency version: installed `gadgetconfig` command version
- host capability class: coarse Pi class such as `pi5`, `pi4-limited`, or
  `pizero-control`

## Install

Preferred install on a Pi:

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
- The broker should reach this service over the private lab network or
  WireGuard; public exposure is not required.

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
