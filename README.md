# Peer-to-Peer VPN with WireGuard!

This script automates the setup of a WireGuard VPN for establishing secure peer-to-peer connections. With support for both the server and client configurations, you can easily deploy a WireGuard VPN network to securely connect devices across different networks.

## Overview

This repository provides a single, multi-use script to streamline the setup of a WireGuard VPN connection:

- `init_wireguard`: Configures a WireGuard VPN server or client, sets up IP routing, and defines the VPN’s network parameters.

The script helps create a private VPN network where multiple clients can connect securely to the server and communicate as if they were on the same local network. This setup is ideal for scenarios requiring secure communication, such as remote administration, file sharing, and secure access to internal resources.
## Prerequisites

- Operating System: Linux (tested on Ubuntu, should work on other distributions with minor adjustments)
- Root or Sudo Access


## Installation

### No setup required!

#### Simply grab the script:

```
wget https://raw.githubusercontent.com/chris-bratti/wireguard-init/refs/heads/master/init_wireguard.sh
```
#### And make it executable:
```
chmod +x init_wireguard.sh
```
## Usage

### Server Setup

#### Run the Server Setup Command:
```
sudo ./init_wireguard.sh init_server -i 10.10.10.1/24 -p 51820
```

Options:
- `-i` (optional): internal address range for wireguard server - defaults to `10.10.10.1/24` if not supplied
- `-p` (optional): port that wireguard will use to communicate with peers - defaults to `51820` if not supplied

#### This command will:
- Install WireGuard
- Generate the server's private and public keys.
- Configure the WireGuard server interface.
- Define the server IP address and port.
- Set up IP forwarding and routing rules.
- Automate adding a peer

The script will give you the option to add a peer and automate the peer configuration. After your server is up and running, you can use the `add_peer` command to add additional peers!

#### Add additional peers
```
sudo ./init_wireguard.sh add_peer -n peerName -d 10.10.10.1 -o 1
```

Options:
- `-n` (optional): name for new peer, will prompt for this value if not supplied
- `-d` (optional): DNS address for new peer to use
- `-o` (optional): peer configuration option, will prompt if not supplied. One of:
    1. QR Code
    2. Client automation script
    3. Manual setup

#### This command will:
- Find the next available IP in the server's address range
- Generate the necessary client configurations
- Provide options to automate peer configuration

The `add_peer` command will generate all the necessary configs to set up a client - even a QR code for mobile clients!

### Client Setup
The `init_server` command gives you a lot of options to configure a new client. However, if you are connecting a headless machine as a VPN client, the client setup option will come in handy!

#### 1. Copy the configuration file

The `init_server` and `add_peer` commands will generate a configuration file that will look something like this for each peer:

```
[Interface]
PrivateKey = <private-key>
Address = 10.8.0.2/24

[Peer]
PublicKey = <public-key>
AllowedIPs = 10.8.0.0/24, fd24:609a:6c18::/64
Endpoint = 203.0.113.1:51820

```

#### 2. Download script to client machine and make it executable

```
wget https://raw.githubusercontent.com/chris-bratti/wireguard-init/refs/heads/master/init_wireguard.sh
chmod +x init_wireguard.sh
```

#### 3. Run the init_client command
```
sudo ./init_wireguard.sh init_client /path/to/config.conf -a
```

Options:
- `/path/to/config` (required): path to the configuration file that was copied onto the client machine
- `-a` (optional): option to run wireguard as a service on the client machine (not typically recommended)

#### This command will:
- Install WireGuard
- Configure the WireGuard client
- Set up IP forwarding and routing rules

#### Connect to the VPN: 

The script can configure WireGuard to run automatically as a service on both the server and the client if desired. However, to manually start and stop the WireGuard service, use:

```
sudo wg-quick up wg0 #starts wireguard

sudo wg-quick down wg0 #stops wireguard
```

## Additional notes

In order for a client to access the Wireguard server remotely, the ListenPort (default value of`51820`) will need to be opened on the server's network. This is typically done through the network's router, and the process will vary between brands.


For additional support, see WireGuard’s Documentation for more in-depth troubleshooting.

## Contributions

Contributions are welcome! Please open an issue or submit a pull request if you have suggestions or improvements.