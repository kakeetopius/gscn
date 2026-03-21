# gscn

A simple and flexible command-line tool for network operations such as host discovery and port scanning. Designed for efficiency and ease of use, `gscn` supports both IPv4 and IPv6.

## Features

- **Host Discovery**: Find hosts on your local network using ARP (IPv4) or ICMP Neighbor Discovery (IPv6).
- **Port Scanning**: Scan hosts for open TCP/UDP ports, with customizable port ranges and concurrency.
- **Reverse DNS Lookup**: Optionally resolve discovered IP addresses to hostnames.
- **MAC Address Vendor Lookup**: Supports lookup of vendors for discovered hosts based on their MAC Addresses.
- **Flexible Target Specification**: Supports single IPs, CIDR notation, IP ranges, domain names, and comma-separated lists.


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
./gscn discover [flags]
```

<details>
<summary>Examples</summary>

- Discover a single host:
  ```
  ./gscn discover -t 10.1.1.1
  ```
- Discover all hosts in a subnet:
  ```
  ./gscn discover -t 10.1.1.1/24
  ```
- Discover a range of IPs:
  ```
  ./gscn discover -t 10.1.1.1-5
  ```
- Discover hosts on the network an interface is connected to:
  ```
  ./gscn discover -i eth0
  ```
- Use IPv6 neighbor discovery:
  ```
  ./gscn discover --six -t 2001:abcd:db22::1
  ```
  </details>

### Scan Hosts

```sh
./gscn scan [flags]
```

<details>
<summary>Examples</summary>

- Scan a single host for specific ports:
  ```
  ./gscn scan -t 10.1.1.1 -p 80,443
  ```
- Scan a subnet for a port range:
  ```
  ./gscn scan -t 10.1.1.1/24 -p 1-100
  ```
- Scan multiple targets:
  ```
  ./gscn scan -t 10.1.1.1,bing.com,10.4.4.4-10 -p 1-100,443,8080
  ```
- Use UDP scan:
  ```
  ./gscn scan -u
  ```
  </details>

## Planned Features

- **WiFi Scanning**: Scan for nearby WiFi networks and devices (coming soon).

## Contributing

Contributions are welcome! Please open issues or pull requests for bug fixes, features, or documentation improvements.

## License

MIT License
