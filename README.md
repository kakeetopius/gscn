# gscn

A simple, cross-platform network scanner written in Go. `gscn` provides host discovery, TCP/UDP port scanning, ICMP ping scanning, Wi-Fi scanning with support for both IPv4 and IPv6.

## Features

- Fast, concurrent port scanning
- IPv4 and IPv6 support
- Host discovery using using various network discovery protocols like ARP (IPv4) and NDP (IPv6)
- ICMP ping scanning
- Reverse DNS hostname resolution
- Send scan results via Discord or Email.
- MAC address vendor lookup
- Wi-Fi network scanning (Linux)
- JSON output
- Flexible target specification (IP, CIDR, ranges, domains, and combinations)

## Requirements

- Go 1.18 or newer (for building from source)
- **Linux:** `libpcap` development headers (`libpcap-dev`, `libpcap-devel`, etc.)
- **Windows:** [Npcap](https://npcap.com/#download)

> [!IMPORTANT]
> ARP, NDP, and ICMP-based scans require administrator/root privileges (or `CAP_NET_RAW` on Linux).

## Installation

### Linux

```sh
git clone https://github.com/kakeetopius/gscn.git
cd gscn
go build -o gscn .

# OR install to your PATH
sudo make install
```

### Windows

Install **Npcap**, then install `gscn` using Go:

```sh
go install github.com/kakeetopius/gscn@latest
```

## Quick Start

Discover hosts on your local network:

```sh
gscn discover arp -i eth0
```

Scan common TCP ports:

```sh
gscn scan tcp 192.168.1.0/24 -p 22,80,443
```

Ping an entire subnet:

```sh
gscn scan ping 192.168.1.0/24
```

## Target Specification

Most commands accept one or more targets as the first positional argument.

| Format                   | Example                                        |
| ------------------------ | ---------------------------------------------- |
| Single IPv4/IPv6 address | `10.1.1.1`, `2001:acad::1`                     |
| CIDR                     | `10.1.1.1/24`, `2001:acad::1/64`               |
| Range                    | `10.1.1.1-10`, `2001:acad::1-10`               |
| Domain                   | `example.com`                                  |
| Mixed targets            | `10.1.1.1,example.com,10.4.4.4-10,10.3.3.3/24` |

<details>
<summary><strong>Global Flags</strong></summary>

These flags are available for every command.

| Flag               | Description                                                      |
| ------------------ | ---------------------------------------------------------------- |
| `--config <file>`  | Use a custom configuration file instead of the default location. |
| `--debug`          | Enable debug logging.                                            |
| `-o, --out <file>` | Save scan results to a file.                                     |
| `-j, --json`       | Print scan results as compact JSON.                              |
| `-P, --pretty`     | Print scan results as pretty-formatted JSON.                     |
| `--notify`         | Send scan results using the configured notifier.                 |

### Examples

```sh
gscn scan tcp 192.168.1.1 -p 80 --json

gscn discover arp --notify

gscn scan ping 192.168.1.0/24 -o results.txt

# scan results printed in pretty JSON form.
gscn scan tcp 10.0.0.0/24 -p 22,80 -jP
```

</details>

## Commands

### **discover**

Discover hosts on IPv4 and IPv6 networks using various network discovery protocols.

<details>
<summary><strong>Show details</strong></summary>

#### 1. discover arp

Discover IPv4 hosts using ARP.

```sh
gscn discover arp [targets] [flags]
```

Sends ARP requests to discover IPv4 hosts on the network.

<details>
<summary><strong>Examples</strong></summary>

```sh
# Discover a single host
gscn discover arp 10.1.1.1

# Discover all hosts in a subnet
gscn discover arp 10.1.1.1/24

# Discover a range of hosts
gscn discover arp 10.1.1.1-5

# Scan the subnet(s) connected to an interface
gscn discover arp -i eth0

# Do a reverse look up to resolve hostnames
gscn discover arp 10.1.1.1/24 --hostnames

# Send results via the configured notifier
gscn discover arp 10.1.1.1/24 --notify
```

</details>

<details>
<summary><strong>Flags</strong></summary>

| Flag                                | Description                                                                                                 |
| ----------------------------------- | ----------------------------------------------------------------------------------------------------------- |
| `-i, --iface <name>`                | Network interface to scan from. When no target is provided, scans the subnet(s) connected to the interface. |
| `-s, --source <ip>`                 | Source IPv4 address to use in ARP packets.                                                                  |
| `-t, --response-timeout <duration>` | Time to wait for ARP replies.                                                                               |
| `-H, --hostnames`                   | Resolve discovered IP addresses to hostnames.                                                               |
| `--vendors`                         | Include MAC address vendor information. Enabled by default.                                                 |

</details>

#### 2. discover ndp

Discover IPv6 hosts using the Neighbor Discovery Protocol.

```sh
gscn discover ndp [targets] [flags]
```

Sends ICMPv6 Neighbor Solicitation packets or optionally reads entries from the kernel neighbor cache.

<details>
<summary><strong>Examples</strong></summary>

```sh
# Discover a single IPv6 host
gscn discover ndp 2001:acad::1

# Discover an IPv6 subnet
gscn discover ndp 2001:acad::1/64

# Discover a range of IPv6 hosts
gscn discover ndp 2001:acad::1-10

# Scan the connected subnet
gscn discover ndp -i eth0

# Read from the kernel neighbor cache
gscn discover ndp -i eth0 --from-cache
```

</details>

<details>
<summary><strong>Flags</strong></summary>

| Flag                                | Description                                                                                              |
| ----------------------------------- | -------------------------------------------------------------------------------------------------------- |
| `-i, --iface <name>`                | Network interface to scan from. When no target is provided, scans the subnet connected to the interface. |
| `-s, --source <ip>`                 | Source IPv6 address to use in Neighbor Solicitation packets.                                             |
| `-t, --response-timeout <duration>` | Time to wait for Neighbor Advertisement replies.                                                         |
| `-H, --hostnames`                   | Resolve discovered IP addresses to hostnames.                                                            |
| `--from-cache`                      | Read from the kernel neighbor cache instead of sending packets.                                          |
| `--vendors`                         | Include MAC address vendor information. Enabled by default.                                              |

</details>

</details>

### **scan**

Carry out different types of scans.

> [!NOTE]
> TCP and UDP scans first perform a ping sweep to determine whether hosts are reachable. Use `--skip-ping` to disable this behavior and scan all targets unconditionally.

<details>
<summary><strong>Show details</strong></summary>

#### 1. scan tcp

Perform a full TCP connect scan.

```sh
gscn scan tcp <targets> [flags]
```

Attempts a complete TCP connection on each specified port.

<details>
<summary><strong>Examples</strong></summary>

```sh
# Scan a single host for the common ports like 22,80 etc
gscn scan tcp 10.1.1.1

# Scan a subnet for the first 100 ports using 300 concurrent workers
gscn scan tcp 10.1.1.1/24 -p 1-100 --workers 300

# Scan mixed targets
gscn scan tcp 10.1.1.1,bing.com,10.4.4.4-10 -p 22,80,443

# Scan an IPv6 host
gscn scan tcp 2001:acad::1 -p 80

# Skip the ping sweep
gscn scan tcp 10.1.1.1/24 -p 22,80 --skip-ping

# Show only open ports on live hosts
gscn scan tcp 10.1.1.1/24 -p 1-1000 --open --up --workers 200

# Send results via the configured notifier
gscn scan tcp 10.1.1.1/24 -p 1-100 --notify
```

</details>

<details>
<summary><strong>Flags</strong></summary>

| Flag                                | Description                                              |
| ----------------------------------- | -------------------------------------------------------- |
| `-p, --ports <ports>`               | Ports to scan. Supports ranges, lists, or combinations.  |
| `-H, --hostnames`                   | Resolve hostnames.                                       |
| `-t, --response-timeout <duration>` | TCP response timeout.                                    |
| `-w, --workers <n>`                 | Number of concurrent workers.                            |
| `--ping-count <n>`                  | Number of ICMP Echo Requests sent during the ping sweep. |
| `--ping-timeout <duration>`         | Ping timeout.                                            |
| `--skip-ping`                       | Skip the initial ping sweep.                             |
| `--open`                            | Show only open ports.                                    |
| `--up`                              | Show only reachable hosts.                               |

</details>

#### 2. scan udp

Perform a UDP scan.

```sh
gscn scan udp <targets> [flags]
```

Infers UDP port state using ICMP Port Unreachable responses or the absence of a response.

<details>
<summary><strong>Examples</strong></summary>

```sh
# Scan common UDP ports
gscn scan udp 10.1.1.1 -p 53,161

# Scan IPv4 and IPv6 hosts
gscn scan udp 10.1.1.1,2001:acad::1 -p 53

# Scan a subnet
gscn scan udp 10.1.1.1/24 -p 1-100

# Increase response timeout
gscn scan udp 10.1.1.1 -p 53,161 --response-timeout 5s
```

</details>

<details>
<summary><strong>Flags</strong></summary>

| Flag                                | Description                                              |
| ----------------------------------- | -------------------------------------------------------- |
| `-p, --ports <ports>`               | Ports to scan.                                           |
| `-H, --hostnames`                   | Resolve hostnames.                                       |
| `-t, --response-timeout <duration>` | UDP response timeout.                                    |
| `-w, --workers <n>`                 | Number of concurrent workers.                            |
| `--ping-count <n>`                  | Number of ICMP Echo Requests sent during the ping sweep. |
| `--ping-timeout <duration>`         | Ping timeout.                                            |
| `--open`                            | Show only open or open\|filtered ports.                  |
| `--up`                              | Show only reachable hosts.                               |

</details>

#### 3. scan ping

Perform an ICMP ping sweep.

```sh
gscn scan ping <targets> [flags]
```

Determines which hosts are reachable without scanning any ports.

<details>
<summary><strong>Examples</strong></summary>

```sh
# Ping a subnet
gscn scan ping 10.1.1.1/24

# Ping with 200 concurrent workers and show only live hosts
gscn scan ping 10.1.1.1/24 --workers 200 --up

# Ping mixed targets
gscn scan ping 10.1.1.1,bing.com

# Ping an IPv6 host
gscn scan ping 2001:acad::1

# Resolve hostnames
gscn scan ping 10.1.1.1/24 --hostnames

# Send results via the configured notifier
gscn scan ping 10.1.1.1/24 --notify
```

</details>

<details>
<summary><strong>Flags</strong></summary>

| Flag                       | Description                           |
| -------------------------- | ------------------------------------- |
| `-H, --hostnames`          | Resolve hostnames.                    |
| `-w, --workers <n>`        | Number of concurrent workers.         |
| `-c, --count <n>`          | Number of ICMP Echo Requests to send. |
| `-t, --timeout <duration>` | Ping timeout.                         |
| `--up`                     | Show only reachable hosts.            |

</details>

</details>

### **wifi**

Scan nearby Wi-Fi networks (Linux only).

<details>
<summary><strong>Show details</strong></summary>

```sh
gscn wifi [flags]
```

Scans nearby Wi-Fi networks and displays SSID, BSSID, signal strength, channel, and security information.

<details>
<summary><strong>Examples</strong></summary>

```sh
# Auto-detect the wireless interface
gscn wifi

# Specify a wifi interface
gscn wifi -i wlo3

# Send results via the configured notifier
gscn wifi -i wlo2 --notify
```

</details>

<details>
<summary><strong>Flags</strong></summary>

| Flag                 | Description                                                                       |
| -------------------- | --------------------------------------------------------------------------------- |
| `-i, --iface <name>` | Wireless interface to use. If omitted, gscn attempts to detect one automatically. |

</details>

</details>

## Configuration

A configuration file is **only required** when using the `--notify` flag.

Default locations:

- **Linux:** `~/.config/gscn.toml`
- **Windows:** `%APPDATA%\gscn.toml`

```toml
[notifier]
type = "discord" # or "email"

[notifier.discord]
token = "your_bot_token"
channel_id = "your_channel_id"
channel_name = "channel_name"

# OR

[notifier.email]
sender_address = "your_email@gmail.com"
receiver_address = "recipient@gmail.com"
sender_name = "gscn network scanner"
app_password = "your_app_password"
```

Use a custom configuration file:

```sh
gscn --config /path/to/gscn.toml scan tcp 10.1.1.1 -p 80 --notify
```

## License

[MIT License](LICENSE)
