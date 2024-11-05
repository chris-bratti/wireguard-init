#!/bin/bash

info_message (){
	echo -e "${CYAN}$1${NC}" >&2
}

success_message (){
	echo -e "${GREEN}$1${NC}" >&2
}

error_message (){
	echo -e "${RED}$1${NC}" >&2
}

validate_config_file (){
    if [ ! -f "$configFile" ]; then
        error_message "Error: Configuration file not found. Please check server script for instructions on running peer setup."
        return 1
    fi

    if ! grep -q "\[Interface\]" "$configFile" || ! grep -q "\[Peer\]" "$configFile";then
        error_message "Error: Configuration file seems to be malformed. Please check server script for instructions on running peer setup."
        return 1
    fi

    cp "$configFile" "$configPath/wg0.conf"
    configFile="$configPath/wg0.conf"
}

init_client (){
    info_message "Validating configuration file...."
    validate_config_file

    info_message "Installing WireGuard...."
    sudo apt update -y > /dev/null
    
    sudo apt install wireguard -y > /dev/null

    device=$(ip route list table main default | awk '{for(i=1;i<=NF;i++) if($i=="dev") print $(i+1)}')

    gatewayAddress=$(ip route list table main default | awk '{for(i=1;i<=NF;i++) if($i=="via") print $(i+1)}')

    ipAddress=$(ip -brief address show $device | awk '{for(i=1;i<=NF;i++) if($i=="UP") print $(i+1)}')

    routeTrafficLines="PostUp = ip rule add table 200 from $ipAddress\nPostUp = ip route add table 200 default via $gateWayAddress\nPreDown = ip rule delete table 200 from $ipAddress\nPreDown = ip route delete table 200 default via $gatewayAddress"

    sed -i "/^Address = [0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\/[0-9]\{1,2\}$/a $routeTrafficLines" $configFile

    sudo apt install resolvconf > /dev/null

# TODO: Option to choose manual or automatic VPN connection
    sudo systemctl enable wg-quick@wg0.service > /dev/null

    sudo systemctl start wg-quick@wg0.service > /dev/null

    if systemctl is-active --quiet wg-quick@wg0.service; then
		success_message "WireGuard server is running!"
	else
		error_message "Error starting WireGuard server, please check logs"
		return 1
	fi
}

scriptPath="$( cd -- "$(dirname "$0")" >/dev/null 2>&1 ; pwd -P )"
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color
configFile=""
configPath="/etc/wireguard"

if [ -n $1 ]; then
    configFile=$1
else
    configFile="$scriptPath/wg0.conf"
fi


init_client