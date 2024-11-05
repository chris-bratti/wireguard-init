#!/bin/bash

# Function to get user input and validate against a given regex pattern
get_user_input () {
	local message=$1
	local regex=$2
	while true; do
		echo -ne "\e[32m$message\e[0m: " >&2
		read userInput
		if [[ $userInput =~ $regex ]]; then
			break
		else
			echo -e "${RED}Invalid input{$NC}" >&2
		fi
	done
	echo $userInput
}

# Function to get y/n input from a user, uses the get_user_input function
get_binary_user_input () {
	local answer=$(get_user_input "$1(y/n)" $binaryOptionRegex)
	answer=$(echo $answer | tr '[:upper:]' '[:lower:]')
	if [[ "$answer" = 'y' || "$answer" = "yes" ]]; then
		return 0
	else
		return 1
	fi
}

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

    echo $configFile

    cp "$configFile" "$configPath/wg0.conf"
    configFile="$configPath/wg0.conf"
}

configure_wg_as_service (){
    # TODO: Check before setting AllowedIps to 0.0.0.0
    info_message "Configuring WireGuard to run automatically...."
    sudo systemctl enable wg-quick@wg0.service > /dev/null

    sudo systemctl start wg-quick@wg0.service > /dev/null

    if systemctl is-active --quiet wg-quick@wg0.service; then
		success_message "WireGuard server is running!"
	else
		error_message "Error starting WireGuard server, please check logs"
		return 1
	fi
    info_message "✅ Done"
}

init_client (){
    info_message "Validating configuration file...."
    validate_config_file
    info_message "✅ Done"

    info_message "Installing WireGuard...."
    sudo apt update -y > /dev/null
    
    sudo apt install wireguard -y > /dev/null

    sudo apt install resolvconf > /dev/null
    info_message "✅ Done"

    #TODO: multiple network device config

    info_message "Configuring client traffic routing...."
    device=$(ip route list table main default | awk '{for(i=1;i<=NF;i++) if($i=="dev") print $(i+1)}')

    gatewayAddress=$(ip route list table main default | awk '{for(i=1;i<=NF;i++) if($i=="via") print $(i+1)}')

    ipAddressSubnet=$(ip -brief address show $device | awk '{for(i=1;i<=NF;i++) if($i=="UP") print $(i+1)}')

    subnetAddressRange=$(echo $ipAddressSubnet | sed 's/\(\([0-9]\{1,3\}\.\)\{3\}\)[0-9]\{1,3\}/\10/')

    ipAddress=$(echo $ipAddressSubnet | sed 's#/.*##')

cat << EOF
#####################################################
# Routing all traffic through the VPN can cause SSH #
#  lockouts for peers you are connecting to through #
#  SSH.                                             #
#                                                   #
# In order to prevent lockouts, please confirm the  #
#  subnet below. Devices on this subnet will be     #
#  able to continue using SSH to connect to the     #
#  client machine                                   #
#####################################################
EOF
    
    if ! get_binary_user_input "Is the address range $subnetAddressRange correct?";then
        echo "Handle case here"
    fi

    routeTrafficLines="PostUp = ip rule add table 200 from $ipAddress\nPostUp = ip route add table 200 default via $gatewayAddress\nPostUp = ip route add $subnetAddressRange via $gatewayAddress\nPreDown = ip rule delete table 200 from $ipAddress\nPreDown = ip route delete table 200 default via $gatewayAddress\nPreDown = ip route delete $subnetAddressRange via $gatewayAddress"

    sed -i "/^Address = [0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\/[0-9]\{1,2\}$/a $routeTrafficLines" $configFile

    info_message "✅ Done"

    

cat << EOF
#####################################################
# WireGuard is currently configured for manual      #
#  start/stop.                                      #
#                                                   #
# You can use wq-quick to manage the service:       #
#     wq-quick start wg0 #Starts wireguard          #
#     wq-quick stop wg0 #Stops wireguard            #
#                                                   #
# You can also configure WireGuard to run           #
#  automatically as a service - though keep in mind #
#  this will mean your client will connect be       #
#  connected to the VPN by default unless WireGuard #
#  is disabled                                      #
#####################################################
EOF
    if get_binary_user_input "Configure WireGuard to start automatically?"; then
        configure_wg_as_service
    else
        info_message "WireGuard will not run automatically, to connect to the wireguard VPN, use wq-quick"
    fi

    sudo wg-quick up wg0 > /dev/null

    if sudo wg | grep -q "latest handshake"; then
        success_message "Client is connected to WireGuard server!"
    else
        #TODO - port
        error_message "Client is not currently connected to WireGuard server"
        info_message "Make sure ListenPort has been forwarded on the server's network"
        info_message "To check connection status, run sudo wg"
    fi 
    
}

scriptPath="$( cd -- "$(dirname "$0")" >/dev/null 2>&1 ; pwd -P )"
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'
configFile=""
configPath="/etc/wireguard"

if [ -n $1 ]; then
    configFile=$1
else
    configFile="$scriptPath/wg0.conf"
fi


init_client