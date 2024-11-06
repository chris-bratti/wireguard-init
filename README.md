# Peer-to-Peer VPN with WireGuard!

These scripts automate the setup of a WireGuard VPN for establishing secure peer-to-peer connections. With a script for both the server and client configurations, you can easily deploy a WireGuard VPN network to securely connect devices across different networks.

## Overview

This repository provides two scripts to streamline the setup of a WireGuard VPN connection:

- `init_wireguard`: Configures a WireGuard VPN server, sets up IP routing, and defines the VPN’s network parameters.
- `init_wg_client`: Configures a WireGuard client, allowing it to securely connect to the server through the VPN.

The scripts help create a private VPN network where multiple clients can connect securely to the server and communicate as if they were on the same local network. This setup is ideal for scenarios requiring secure communication, such as remote administration, file sharing, and secure access to internal resources.
## Prerequisites

- Operating System: Linux (tested on Ubuntu, should work on other distributions with minor adjustments)
- Root or Sudo Access: Both server and client setup scripts require root privileges.


## Installation

### No setup required!

#### Simply clone the repository:

```
git clone https://github.com/chris-bratti/wireguard-init.git
cd wireguard-peer-setup
```
#### And make the scripts executable:
```
chmod +x init_wireguard.sh
chmod +x init_wg_client.sh
```
## Usage

### Server Setup

#### Run the Server Setup Script:
```
sudo ./init_wireguard.sh init_server
```
#### This script will:
- Install WireGuard
- Generate the server's private and public keys.
- Configure the WireGuard server interface.
- Define the server IP address and port.
- Set up IP forwarding and routing rules.
- Provide options to automate client configuration

The server script will generate all the necessary configs to set up a client - even a QR code for mobile clients!

### Client Setup
If you are connecting a headless machine as a VPN client, the client setup script will come in handy! Copy the configuration file provided by the server script and pass it into the client script.
#### Run the Client Setup Script:

```
sudo ./init_wg_client.sh /path/to/config.conf
```
#### This script will:
- Install WireGuard
- Configure the WireGuard client
- Set up IP forwarding and routing rules

#### Connect to the VPN: 

The script can configure WireGuard to run automatically as a service. Otherwise, to start and stop wireguard, use:

```
sudo wg-quick up wg0 #starts wireguard

sudo wg-quick down wg0 #stops wireguard
```

## Additional notes

In order for a client to access the Wireguard server remotely, the ListenPort (default value of`51820`) will need to be opened on the server's network. This is typically done through the network's router, and the process will vary between brands.



For additional support, see WireGuard’s Documentation for more in-depth troubleshooting.

## Contributions

Contributions are welcome! Please open an issue or submit a pull request if you have suggestions or improvements.