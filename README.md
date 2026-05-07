# gscn

A simple and flexible command-line tool for network operations such as host discovery and port scanning. Designed for efficiency and ease of use, `gscn` supports both IPv4 and IPv6.

- **Host Discovery**: Find hosts on your local network using ARP (IPv4) or ICMP Neighbor Discovery (IPv6).
- **Port Scanning**: Scan hosts for open TCP/UDP ports, with customizable port ranges and concurrency.
- **Reverse DNS Lookup**: Optionally resolve discovered IP addresses to hostnames.
- **MAC Address Vendor Lookup**: Supports lookup of vendors for discovered hosts based on their MAC Addresses.
- **Flexible Target Specification**: Supports single IPs, CIDR notation, IP ranges, domain names, and comma-separated lists.
- **Notifications**: Send scan results via Discord or Email with configurable notifiers.
- **WiFi Scanning**: Scan for nearby WiFi networks and display detailed information about them.
- **Cross Platform**: Works on both windows and linux.

## Requirements

- Go (1.18 or newer) installed and available in your PATH for building from source.
- For Linux: libpcap development headers (e.g., `libpcap-dev` on Debian/Ubuntu, `libpcap-devel` on Fedora/CentOS) for packet capture features.
- For Windows: npcap which can be obtained [here](https://npcap.com/#download).

## Installation

On Linux
Clone the repository and build with Go:

```sh
git clone https://github.com/kakeetopius/gscn.git
cd gscn
go build -o gscn .

#OR to install to your PATH on linux
sudo make install
```

On Windows.
If npcap is successfully installed, you can simply install with Go.

```sh
go install github.com/kakeetopius/gscn@latest
```

## Usage

### Discover Hosts on a Local Network.

```sh
gscn discover [flags]
```

<details>
<summary>Examples</summary>

- Discover a single host:
  ```sh
  gscn discover 10.1.1.1
  ```
- Discover all hosts that are up in a local subnet:
  ```sh
  gscn discover 10.1.1.1/24
  ```
- Check if a range of IPs are up on a local network:
  ```sh
  gscn discover 10.1.1.1-5
  ```
- Discover hosts on the network an interface is connected to:
  ```sh
  gscn discover eth0
  ```
- Use IPv6 neighbor discovery:
  ```sh
  gscn discover -6 2001:abcd:db22::1
  ```
- Discover hosts and send results via Discord/Email:
  ```sh
  gscn discover 10.1.1.1/24 --notify
  ```
  </details>

### Scan Hosts

```sh
gscn scan [flags]
```

<details>
<summary>Examples</summary>

- Scan a single host for specific ports:
  ```sh
  gscn scan 10.1.1.1 -p 80,443
  ```
- Scan a subnet for a port range:
  ```sh
  gscn scan 10.1.1.1/24 -p 1-100
  ```
- Scan multiple targets:
  ```sh
  gscn scan 10.1.1.1,bing.com,10.4.4.4-10 -p 1-100,443,8080
  ```
- Use UDP scan:
  ```sh
  gscn scan 10.1.1.1,2001:acad:abcd::1 -p 53,500,989 --udp
  ```
- Carry out a ping scan for a whole network to check which hosts are up with 200 concurrent workers
  ```sh
  gscn scan 10.1.1.1/24 --ping --workers 200
  ```
- Scan and notify results:
  ```sh
  gscn scan 10.1.1.1/24 -p 1-100 --notify
  ```
  </details>

### Wi-Fi Scanning

```sh
gscn wifi [flags]
```

<details>
<summary>Examples</summary>

- Scan for nearby WiFi networks:

```sh
gscn wifi
```

- Scan on a specific WiFi interface:

```sh
gscn wifi -i wlo3
```

- Send scan results via a configured notifier:

```sh
gscn wifi -i wlo2 --notify
```

</details>

## Configuration

> [!NOTE]
> This is only required if notifications are desired.

Create a configuration file at:

**On Linux:**

- `~/.config/gscn.toml`

**On Windows:**

- `%APPDATA%\gscn.toml` or for powershell `$env:APPDATA/gscn.toml`

```toml
[notifier]
type = "discord"  # or "email"

[notifier.discord]
token = "your_bot_token"
channel_id = "your_channel_id"
channel_name = "channel_name" #can be omitted if channel_id is given

#OR
[notifier.email]
sender_address = "your_email@gmail.com"
receiver_address = "recipient@gmail.com"
sender_name = "gscn network scanner" # or any name you want to appear as email sender
app_password = "your_app_password"
```

## Contributing

Contributions are welcome! Please open issues or pull requests for bug fixes, features, or documentation improvements.

## License

[MIT License](LICENSE)
