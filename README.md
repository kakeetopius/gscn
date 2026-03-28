# gscn

A simple and flexible command-line tool for network operations such as host discovery and port scanning. Designed for efficiency and ease of use, `gscn` supports both IPv4 and IPv6.

## Features

- **Host Discovery**: Find hosts on your local network using ARP (IPv4) or ICMP Neighbor Discovery (IPv6).
- **Port Scanning**: Scan hosts for open TCP/UDP ports, with customizable port ranges and concurrency.
- **Reverse DNS Lookup**: Optionally resolve discovered IP addresses to hostnames.
- **MAC Address Vendor Lookup**: Supports lookup of vendors for discovered hosts based on their MAC Addresses.
- **Flexible Target Specification**: Supports single IPs, CIDR notation, IP ranges, domain names, and comma-separated lists.
- **Notifications**: Send scan results via Discord or Email with configurable notifiers.

## Installation

Clone the repository and build with Go:

```sh
git clone https://github.com/kakeetopius/gscn.git
cd gscn

go build -o gscn .

#OR to install to your PATH
sudo make install
```

## Usage

### Discover Hosts

```sh
gscn discover [flags]
```

<details>
<summary>Examples</summary>

- Discover a single host:
  ```
  gscn discover -t 10.1.1.1
  ```
- Discover all hosts in a subnet:
  ```
  gscn discover -t 10.1.1.1/24
  ```
- Discover a range of IPs:
  ```
  gscn discover -t 10.1.1.1-5
  ```
- Discover hosts on the network an interface is connected to:
  ```
  gscn discover -i eth0
  ```
- Use IPv6 neighbor discovery:
  ```
  gscn discover --six -t 2001:abcd:db22::1
  ```
- Discover hosts and send results via Discord/Email:
  ```
  gscn discover -t 10.1.1.1/24 --notify
  ```
  </details>

### Scan Hosts

```sh
gscn scan [flags]
```

<details>
<summary>Examples</summary>

- Scan a single host for specific ports:
  ```
  gscn scan -t 10.1.1.1 -p 80,443
  ```
- Scan a subnet for a port range:
  ```
  gscn scan -t 10.1.1.1/24 -p 1-100
  ```
- Scan multiple targets:
  ```
  gscn scan -t 10.1.1.1,bing.com,10.4.4.4-10 -p 1-100,443,8080
  ```
- Use UDP scan:
  ```
  gscn scan -t 10.1.1.1,2001:acad:abcd::1 -p 53,500,989 --udp
  ```
- Carry out a ping scan for a whole network to check which hosts are up with 200 concurrent workers
  ```
  gscn scan -t 10.1.1.1/24 --ping --workers 200
  ```
- Scan and notify results:
  ```
  gscn scan -t 10.1.1.1/24 -p 1-100 --notify
  ```
  </details>

## Configuration

> [!NOTE]
> This is only required if notifications are desired.

Create a configuration file at `~/.config/gscn.toml`:

```toml
[notifier]
type = "discord"  # or "email"

[notifier.discord]
token = "your_bot_token"
channel_id = "your_channel_id"
channel_name = "channel_name" #can be omitted if channel_id is given

#OR
[notifier.email]
sender = "your_email@gmail.com"
receiver = "recipient@gmail.com"
from = "gscn network scanner" # or any name you want to appear as email sender
app_password = "your_app_password"

```

## Planned Features

- **WiFi Scanning**: Scan for nearby WiFi networks and devices (coming soon).

## Contributing

Contributions are welcome! Please open issues or pull requests for bug fixes, features, or documentation improvements.

## License

[MIT License](LICENSE)
