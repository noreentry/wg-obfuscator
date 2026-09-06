# udp-pktunnel — plain UDP relay with pktstats

Symmetric UDP forwarder (no WireGuard obfuscation, no STUN). Optional 4-byte XOR
seq trailer and binary stats dumps (`pktstats.c` format, compatible with
`scripts/correlate-pktstats.py`).

## Build

```bash
make udp-pktunnel
```

## Config (`udp-pktunnel.conf`)

```ini
[main]
source-lport = 20004
target = 127.0.0.1:5201
stats-dir = ./stats
stats-interval = 5
stats-seq = true
verbose = INFO
log-file = ./logs/tunnel.log
log-timestamps = true
```

| Option | Meaning |
|--------|---------|
| `source-lport` | UDP listen port (local apps or WAN clients) |
| `target` | `host:port` to forward decoded payloads to |
| `stats-dir` | Binary dump directory (enables pktstats) |
| `stats-seq` | Append/strip 4-byte seq trailer on the tunnel leg |
| `role` | `client` (oraa) or `server` (siteagw WAN inbound) — flips trailer append/strip |

## Console traffic summary (stderr)

Every **5 seconds** on wall-clock boundaries (`…:00`, `…:05`, `…:10`, …) the
process prints one line to **stderr** (always, even when `log-file` is set):

```
[1757157005] tunnel main: sent 1234 pkts 9.87 Mbit/s  recv 1200 pkts 9.50 Mbit/s
```

Counts and rates are for the completed 5-second interval. Idle intervals report
`0 pkts 0.00 Mbit/s`. View with `journalctl -u … -f` or when running in the
foreground.

## Example: oraa → siteagw (between wg-obfuscators)

Repo configs: `nrn-infra/hosts/oraa/services/udp-pktunnel/` and
`hosts/siteagw/services/udp-pktunnel/`.

```
oraa:  wg0 → obf :21003 → pktunnel :20003 ──WAN :20003──► siteagw pktunnel → obf2 :21003 → wg :51820
```

**oraa** obf `source-lport = 21003`, `target = 127.0.0.1:20003`, pktunnel `role = client`.

**siteagw** pktunnel `role = server`, `source-lport = 20003`, `target = 127.0.0.1:21003`.
Obf2 `source-lport = 21003`. Existing WAN DNAT for **20003** unchanged.

## Example: oraa → siteagw iperf without WireGuard

**siteagw** (`target` = local iperf):

```ini
source-lport = 20004
target = 127.0.0.1:5201
stats-dir = ~/prjs/wg-obfuscator/stats-tunnel
```

**oraa** (`target` = siteagw via WAN):

```ini
source-lport = 20004
target = 178.218.119.173:20004
stats-dir = ~/prjs/wg-obfuscator/stats-tunnel
```

Run tunnel on both ends, then on oraa:

```bash
iperf3 -c 127.0.0.1 -p 20004 -u -b 10M -t 15
```

`iperf3` uses TCP for control; the tunnel is **UDP-only**. For UDP data tests use
`-u` (control still needs TCP reachability to the **final** iperf server, so point
`target` at `127.0.0.1:5201` on the server side and send iperf to the local tunnel
port on the client — the tunnel carries UDP payloads only).

## Correlate dumps

```bash
python3 scripts/correlate-pktstats.py stats-oraa stats-siteagw \
  --sender-name oraa --receiver-name siteagw
```
