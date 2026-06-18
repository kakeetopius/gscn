# gscn

A simple and flexible command-line tool for network operations such as host discovery and port scanning. Designed for efficiency and ease of use, `gscn` supports both IPv4 and IPv6.

- **Host Discovery**: Find hosts on your local network using ARP (IPv4) or ICMP Neighbour Discovery (IPv6).
- **Port Scanning**: Scan hosts for open TCP/UDP ports with customizable port ranges and concurrency.
- **Ping Scanning**: Check host reachability across a network or subnet.
- **Reverse DNS Lookup**: Optionally resolve discovered IP addresses to hostnames.
- **MAC Address Vendor Lookup**: Look up vendors for discovered hosts based on their MAC addresses.
- **Flexible Target Specification**: Supports single IPs, CIDR notation, IP ranges, domain names, and comma-separated combinations of the above.
- **Notifications**: Send scan results via Discord or Email with configurable notifiers.
- **WiFi Scanning**: Scan for nearby WiFi networks and display detailed information about them. (Linux only)
- **Cross Platform**: Works on both Windows and Linux.

## Requirements

- Go (1.18 or newer) installed and available in your PATH for building from source.
- For Linux: libpcap development headers (e.g., `libpcap-dev` on Debian/Ubuntu, `libpcap-devel` on Fedora/CentOS) for packet capture features.
- For Windows: npcap, which can be obtained [here](https://npcap.com/#download).

## Installation

**On Linux** — clone the repository and build with Go:

```sh
git clone https://github.com/kakeetopius/gscn.git
cd gscn
go build -o gscn .

# OR install to your PATH
sudo make install
```

**On Windows** — if npcap is successfully installed, install with Go directly:

```sh
go install github.com/kakeetopius/gscn@latest
```

## Target Specification

Most commands accept one or more targets as the first positional argument. Targets can be specified as:

| Format                      | Example                                     |
| --------------------------- | ------------------------------------------- |
| Single IP (IPv4 or IPv6)    | `10.1.1.1`, `2001:acad::1`                  |
| CIDR range                  | `10.1.1.1/24`, `2001:acad::1/64`            |
| Dash range                  | `10.1.1.1-10`, `2001:acad::1-10`            |
| Domain name                 | `example.com`                               |
| Comma-separated combination | `10.1.1.1,bing.com,10.4.4.4-10,10.3.3.3/24` |

## Usage

### Discover Hosts on a Local Network

```sh
gscn discover <subcommand> [flags]
```

`discover` has two subcommands depending on the protocol you want to use. Both require raw packet access, so `gscn discover` typically needs to be run as root or with the appropriate capabilities (`CAP_NET_RAW`).

#### `gscn discover arp` — IPv4 host discovery via ARP

Sends ARP requests to target IPv4 addresses and listens for replies.

```sh
gscn discover arp [targets] [flags]
```

| Flag                                | Description                                                                                                        |
| ----------------------------------- | ------------------------------------------------------------------------------------------------------------------ |
| `-i, --iface <name>`                | Network interface to scan from. When used without a target, scans the entire subnet the interface is connected to. |
| `-s, --source <ip>`                 | Source IP address to embed in ARP packets. Defaults to the address of the selected interface.                      |
| `-t, --response-timeout <duration>` | Time to wait for ARP replies (e.g. `500ms`, `3s`).                                                                 |
| `-H, --hostnames`                   | Perform a reverse DNS lookup on each discovered address to resolve hostnames.                                      |
| `--vendors`                         | Include MAC address vendor information in results. Enabled by default; pass `--vendors=false` to disable.          |

<details>
<summary>Examples</summary>

```sh
# Discover a single host
gscn discover arp 10.1.1.1

# Discover all hosts in a subnet
gscn discover arp 10.1.1.1/24

# Discover a range of hosts
gscn discover arp 10.1.1.1-5

# Discover all hosts on the network an interface is connected to
gscn discover arp -i eth0

# Discover with reverse DNS lookup and vendor info
gscn discover arp 10.1.1.1/24 --hostnames

# Send results via Discord/Email
gscn discover arp 10.1.1.1/24 --notify
```

</details>

#### `gscn discover ndp` — IPv6 host discovery via Neighbour Discovery Protocol

Sends ICMPv6 Neighbour Solicitation messages to discover hosts on an IPv6 subnet. Can also read from the kernel's cached neighbour table without sending any packets.

```sh
gscn discover ndp [targets] [flags]
```

| Flag                                | Description                                                                                                                         |
| ----------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------- |
| `-i, --iface <name>`                | Network interface to scan from. When used without a target, scans the entire subnet the interface is connected to.                  |
| `-s, --source <ip>`                 | Source IPv6 address to embed in NDP packets. Defaults to the address of the selected interface.                                     |
| `-t, --response-timeout <duration>` | Time to wait for NDP replies (e.g. `500ms`, `3s`).                                                                                  |
| `-H, --hostnames`                   | Perform a reverse DNS lookup on each discovered address to resolve hostnames.                                                       |
| `--from-cache`                      | Read from the kernel's neighbour cache instead of actively probing hosts. Faster and passive, but may miss hosts not recently seen. |
| `--vendors`                         | Include MAC address vendor information in results. Enabled by default; pass `--vendors=false` to disable.                           |

<details>
<summary>Examples</summary>

```sh
# Discover a single IPv6 host
gscn discover ndp 2001:acad::1

# Discover all hosts in an IPv6 subnet
gscn discover ndp 2001:acad::1/64

# Discover a range of IPv6 hosts
gscn discover ndp 2001:acad::1-10

# Discover hosts on the subnet an interface is connected to
gscn discover ndp -i eth0

# Use the kernel's cached neighbour table (no packets sent)
gscn discover ndp -i eth0 --from-cache
```

</details>

---

### Scan Hosts

```sh
gscn scan <subcommand> [flags]
```

`scan` has three subcommands: `tcp`, `udp`, and `ping`. Before scanning ports, `tcp` and `udp` will by default first ping each target to check if it is up, skipping hosts that don't respond. Use `--skip-ping` to disable this behaviour and scan all targets unconditionally.

#### `gscn scan tcp` — TCP full connect scan

Attempts a full TCP connection on each port.

```sh
gscn scan tcp <targets> [flags]
```

| Flag                                | Description                                                                                         |
| ----------------------------------- | --------------------------------------------------------------------------------------------------- |
| `-p, --ports <ports>`               | Ports to scan. Accepts ranges (`1-100`), lists (`80,443,8080`), or combinations (`1-100,443,8080`). |
| `-H, --hostnames`                   | Perform a reverse DNS lookup on each target address.                                                |
| `-t, --response-timeout <duration>` | Time to wait for a TCP response per port (e.g. `500ms`, `5s`).                                      |
| `-w, --workers <n>`                 | Number of concurrent workers (max 500).                                                             |
| `--ping-count <n>`                  | Number of ICMP Echo Requests to send to each host during the pre-scan ping check.                   |
| `--ping-timeout <duration>`         | Time to wait for ping replies. Defaults to 1s multiplied by `--ping-count`.                         |
| `--skip-ping`                       | Skip the pre-scan ping check and attempt to scan all targets regardless of reachability.            |
| `--open`                            | Only show ports that are open or possibly filtered.                                                 |
| `--up`                              | Only show results for hosts that responded to the ping check.                                       |

<details>
<summary>Examples</summary>

```sh
# Scan a single host for specific ports
gscn scan tcp 10.1.1.1 -p 80,443

# Scan a subnet for a port range
gscn scan tcp 10.1.1.1/24 -p 1-100

# Scan multiple mixed targets and port specs
gscn scan tcp 10.1.1.1,bing.com,10.4.4.4-10,10.3.3.3/24 -p 1-100,443,8096

# Scan an IPv6 host
gscn scan tcp 2001:acad::1 -p 80

# Skip the initial ping check and scan all hosts directly
gscn scan tcp 10.1.1.1/24 -p 22,80,443 --skip-ping

# Only show open ports on live hosts, using 200 workers
gscn scan tcp 10.1.1.1/24 -p 1-1000 --open --up --workers 200

# Send results via a configured notifier
gscn scan tcp 10.1.1.1/24 -p 1-100 --notify
```

</details>

#### `gscn scan udp` — UDP scan

Sends UDP packets to each target port and infers port state from ICMP Port Unreachable responses (closed) or the absence of a response (open|filtered).

```sh
gscn scan udp <targets> [flags]
```

| Flag                                | Description                                                                       |
| ----------------------------------- | --------------------------------------------------------------------------------- |
| `-p, --ports <ports>`               | Ports to scan. Accepts ranges (`1-100`), lists (`53,500`), or combinations.       |
| `-H, --hostnames`                   | Perform a reverse DNS lookup on each target address.                              |
| `-t, --response-timeout <duration>` | Time to wait for a response per port.                                             |
| `-w, --workers <n>`                 | Number of concurrent workers (max 500).                                           |
| `--ping-count <n>`                  | Number of ICMP Echo Requests to send to each host during the pre-scan ping check. |
| `--ping-timeout <duration>`         | Time to wait for ping replies. Defaults to 1s multiplied by `--ping-count`.       |
| `--open`                            | Only show ports that are open or possibly filtered.                               |
| `--up`                              | Only show results for hosts that responded to the ping check.                     |

<details>
<summary>Examples</summary>

```sh
# Scan common UDP ports on a single host
gscn scan udp 10.1.1.1 -p 53,500,989

# Scan mixed IPv4 and IPv6 targets
gscn scan udp 10.1.1.1,2001:acad:abcd::1 -p 53,500,989

# Scan a subnet
gscn scan udp 10.1.1.1/24 -p 1-100

# Increase timeout for slow or distant hosts
gscn scan udp 10.1.1.1 -p 53,161 --response-timeout 5s
```

</details>

#### `gscn scan ping` — Ping scan

Sends ICMP Echo Requests to each target to determine which hosts are up, without scanning any ports.

```sh
gscn scan ping <targets> [flags]
```

| Flag                       | Description                                                            |
| -------------------------- | ---------------------------------------------------------------------- |
| `-H, --hostnames`          | Perform a reverse DNS lookup on each target address.                   |
| `-w, --workers <n>`        | Number of concurrent workers (max 500).                                |
| `-c, --count <n>`          | Number of ICMP Echo Request packets to send per host.                  |
| `-t, --timeout <duration>` | Time to wait for ping replies. Defaults to 1s multiplied by `--count`. |
| `--up`                     | Only show results for hosts that are up.                               |

<details>
<summary>Examples</summary>

```sh
# Ping scan a whole subnet
gscn scan ping 10.1.1.1/24

# Only show live hosts, using 200 workers
gscn scan ping 10.1.1.1/24 --workers 200 --up

# Ping scan multiple mixed targets
gscn scan ping 10.1.1.1,bing.com,10.4.4.4-10,10.3.3.3/24

# Ping an IPv6 address
gscn scan ping 2001:acad::1

# Resolve hostnames for live hosts
gscn scan ping 10.1.1.1/24 --up --hostnames

# Send results via a configured notifier
gscn scan ping 10.1.1.1/24 --notify
```

</details>

---

### Wi-Fi Scanning (Linux only)

Scans for nearby Wi-Fi networks and displays details such as SSID, BSSID, signal strength, channel, and security type.

```sh
gscn wifi [flags]
```

| Flag                 | Description                                                           |
| -------------------- | --------------------------------------------------------------------- |
| `-i, --iface <name>` | Wi-Fi interface to use when scanning. Auto-detected if not specified. |

<details>
<summary>Examples</summary>

```sh
# Scan for nearby Wi-Fi networks (auto-detect interface)
gscn wifi

# Scan on a specific interface
gscn wifi -i wlo3

# Send scan results via a configured notifier
gscn wifi -i wlo2 --notify
```

</details>

---

## Configuration

> [!NOTE]
> A configuration file is only required if you want to use the `--notify` flag to send results via Discord or Email.

Create the configuration file at:

- **Linux:** `~/.config/gscn.toml`
- **Windows:** `%APPDATA%\gscn.toml` (or `$env:APPDATA/gscn.toml` in PowerShell)

```toml
[notifier]
type = "discord"  # or "email"

[notifier.discord]
token = "your_bot_token"
channel_id = "your_channel_id"
channel_name = "channel_name"  # can be omitted if channel_id is provided

# OR

[notifier.email]
sender_address = "your_email@gmail.com"
receiver_address = "recipient@gmail.com"
sender_name = "gscn network scanner"
app_password = "your_app_password"
```

To use a config file at a custom path, pass `--config` before the subcommand:

```sh
gscn --config /path/to/gscn.toml scan tcp 10.1.1.1 -p 80 --notify
```

## License

[MIT License](LICENSE)
