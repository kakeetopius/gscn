# gscn

A simple, cross-platform network scanner written in Go. `gscn` can do host discovery, port scanning, ping sweeps, and Wi-Fi scanning from a single CLI.

## Features

- Host discovery with **ARP** (IPv4) and **NDP** (IPv6), either actively or passively
- Discovery of **IPv6 routers**, **DHCPv4/DHCPv6 servers**, and **CDP** neighbours (Cisco devices)
- Fast, concurrent **TCP (connect and SYN)**, **UDP**, and **ICMP ping** scans
- Service banner grabbing on open TCP ports. (Still a Work in Progress)
- IPv4 and IPv6 support, with flexible target specification (IP, CIDR, ranges, domains)
- Reverse DNS hostname resolution and MAC address vendor lookup
- Wi-Fi network scanning (Linux)
- JSON output, file output, and result notifications via Discord or Email

## Requirements

- Go 1.18 or newer (to build from source)
- **Linux:** `libpcap` development headers (`libpcap-dev`, `libpcap-devel`, etc.)
- **Windows:** [Npcap](https://npcap.com/#download)

> [!IMPORTANT]
> Anything that sends or captures raw packets (ARP, NDP, DHCP, CDP, SYN and ICMP scans) needs administrator/root privileges, or `CAP_NET_RAW` on Linux.

## Installation

**Linux**

```sh
git clone https://github.com/kakeetopius/gscn.git
cd gscn
go build -o gscn .

# or install to your PATH
sudo make install
```

**Windows**

Install Npcap, then:

```sh
go install github.com/kakeetopius/gscn@latest
```

## Commands Overview

| Command                       | What it does                                      |
| ----------------------------- | ------------------------------------------------- |
| `gscn discover arp`           | Find IPv4 hosts with ARP                          |
| `gscn discover ndp neighbors` | Find IPv6 hosts with Neighbour Discovery          |
| `gscn discover ndp routers`   | Find IPv6 routers                                 |
| `gscn discover dhcp`          | Find DHCPv4 servers                               |
| `gscn discover dhcp6`         | Find DHCPv6 servers                               |
| `gscn discover cdp`           | Find devices advertising Cisco Discovery Protocol |
| `gscn scan tcp`               | TCP connect scan                                  |
| `gscn scan syn`               | TCP SYN (half-open) scan                          |
| `gscn scan udp`               | UDP scan                                          |
| `gscn scan ping`              | ICMP ping sweep                                   |
| `gscn wifi`                   | Scan nearby Wi-Fi networks (Linux only for now)   |

Run `gscn <command> --help` for the full flag list of any command.

## Targets

Commands that take targets accept one or more, separated by spaces.

| Format                   | Example                                        |
| ------------------------ | ---------------------------------------------- |
| Single IPv4/IPv6 address | `10.1.1.1` `2001:acad::1`                      |
| CIDR                     | `10.1.1.1/24` `2001:acad::1/64`                |
| Range                    | `10.1.1.1-10` `2001:acad::1-10`                |
| Domain                   | `example.com` _(scan commands only)_           |
| Mixed                    | `10.1.1.1 example.com 10.4.4.4-10 10.3.3.3/24` |

`discover` commands accept IP addresses, CIDRs, and ranges only. Domains work with `scan`.

## Global Flags

Available on every command.

| Flag               | Description                                 |
| ------------------ | ------------------------------------------- |
| `--config <file>`  | Use a custom configuration file.            |
| `--debug`          | Enable debug logging.                       |
| `-o, --out <file>` | Save scan results to a file.                |
| `-j, --json`       | Print results as compact JSON.              |
| `-P, --pretty`     | Print results as pretty-formatted JSON.     |
| `--notify`         | Send results using the configured notifier. |

```sh
gscn scan tcp 192.168.1.1 -p 80 --json
gscn scan ping 192.168.1.0/24 -o results.txt
gscn scan tcp 10.0.0.0/24 -p 22,80 -jP   # pretty JSON
```

## discover

Find devices on the local network using link-layer discovery protocols.

### Flags shared by most discover commands

| Flag                                | Description                                                                 |
| ----------------------------------- | --------------------------------------------------------------------------- |
| `-i, --iface <name>`                | Interface(s) to use. Repeat or comma-separate for several. Omit to use all. |
| `-t, --response-timeout <duration>` | How long to wait for responses.                                             |
| `-H, --hostnames`                   | Reverse-lookup hostnames                                                    |
| `--vendors`                         | Add MAC address vendor info. On by default                                  |

### arp

Discover IPv4 hosts with ARP.

```sh
gscn discover arp [targets] [flags]
```

```sh
gscn discover arp 10.1.1.1/24            # a subnet
gscn discover arp 10.1.1.1-5             # a range
gscn discover arp -i eth0                # every subnet on an interface
gscn discover arp -i eth0 --passive      # listen only, send nothing
gscn discover arp -i eth0 --from-cache   # read the kernel neighbour table
```

### ndp neighbors

Discover IPv6 hosts with ICMPv6 Neighbour Discovery.

```sh
gscn discover ndp neighbors <targets> -i <iface> [flags]
```

```sh
gscn discover ndp neighbors -i eth0
gscn discover ndp neighbors 2001:acad::1/64 -i eth0
gscn discover ndp neighbors -i eth0 --from-cache  # don't send out any probes, rather read neighbor info from the kernel neighbor cache. (linux only)
```

### ndp routers

Discover IPv6-enabled routers on the local network.

```sh
gscn discover ndp routers [flags]
```

```sh
gscn discover ndp routers                       # probe for Ipv6 enabled routers (using ICMPv6 Router Solicitations) on all interfaces
gscn discover ndp routers -i eth0 --passive     # passively listen for Router Advertisements on eth0
```

### dhcp / dhcp6

Discover DHCPv4 (`dhcp`) or DHCPv6 (`dhcp6`) servers on the connected networks. Useful for spotting rogue DHCP servers.

```sh
gscn discover dhcp [flags]
gscn discover dhcp6 [flags]
```

```sh
gscn discover dhcp                         # actively probe on all interfaces
gscn discover dhcp -i eth0 --passive       # dont actively probe, just listen for DHCP Offers
gscn discover dhcp6 -i eth0 -H             # try resolve server hostnames
```

### cdp

Listen for devices advertising the Cisco Discovery Protocol. CDP packets are sent periodically (roughly once a minute), so this command waits longer by default.

```sh
gscn discover cdp [-i <iface>] [-t <duration>]
```

```sh
gscn discover cdp -i eth0
gscn discover cdp -t 2m      # wait up to two minutes
```

## scan

Scan hosts and ports on any network. Scans start with a ping sweep to find live hosts (can be skiped with `--skip-ping`).

### Flags shared by tcp, syn, and udp

| Flag                                | Description                                               |
| ----------------------------------- | --------------------------------------------------------- |
| `-p, --ports <ports>`               | Ports to scan: ranges, lists, or both (`1-100,443,8080`). |
| `-H, --hostnames`                   | Reverse-lookup hostnames.                                 |
| `-t, --response-timeout <duration>` | How long to wait for responses.                           |
| `-w, --workers <n>`                 | Concurrent workers (max `500`).                           |
| `--ping-count <n>`                  | ICMP Echo Requests sent during the ping sweep.            |
| `--ping-timeout <duration>`         | How long to wait for ping replies.                        |
| `--open`                            | Show only open ports.                                     |
| `--up`                              | Show only reachable hosts.                                |

### tcp

Full TCP connect scan: completes a handshake on every port.

```sh
gscn scan tcp 10.1.1.1                                        # scans common ports
gscn scan tcp 10.1.1.1 -p all                                 # all ports (1-65535)
gscn scan tcp 10.1.1.1 -p common,90,69                        # common ports plus some others.
gscn scan tcp 10.1.1.1/24 -p 1-100 --workers 200
gscn scan tcp 10.1.1.1 example.com 10.4.4.4-10 -p 22,80,443
gscn scan tcp 2001:acad::1 -p 80
gscn scan tcp 10.1.1.1/24 -p 22,80 --skip-ping
gscn scan tcp 10.1.1.1/24 -p 1-1000 --open --up -w 200
```

### syn

Half-open SYN scan. Sends raw SYN packets and infers port state from the reply without completing the handshake. Needs root.

```sh
gscn scan syn 10.1.1.1/24 -p 1-100 --workers 300
gscn scan syn 2001:acad::1 -p 80
```

### udp

UDP scan. Port state is inferred from ICMP Port Unreachable replies or the lack of any response.

```sh
gscn scan udp 10.1.1.1 -p 53,161
gscn scan udp 10.1.1.1 2001:acad::1 -p 53
gscn scan udp 10.1.1.1 -p 53,161 --response-timeout 5s
```

### ping

ICMP ping sweep. Uses raw ICMP when running as root on Linux, and falls back to UDP-based probes otherwise.

```sh
gscn scan ping 10.1.1.1/24
gscn scan ping 10.1.1.1/24 --workers 200 --up
gscn scan ping 10.1.1.1 example.com
gscn scan ping 2001:acad::1
```

## wifi

Scan nearby Wi-Fi networks (Linux only). Shows SSID, BSSID, signal strength, channel, security type, etc.

```sh
gscn wifi                       # auto-detect the wireless interface
gscn wifi -i wlo3               # pick an interface
gscn wifi -s KPLNet,Office      # only show these SSIDs
```

## Configuration

A config file is **only needed** for `--notify`.

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

Use a custom config file:

```sh
gscn --config /path/to/gscn.toml scan tcp 10.1.1.1 -p 80 --notify
```

## License

[MIT License](LICENSE)
