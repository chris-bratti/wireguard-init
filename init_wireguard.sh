#!/bin/bash

# Prints welcome banner
print_banner() {
	clear
	banner="
__        ___           ____                     _   ___       _ _   
\ \      / (_)_ __ ___ / ___|_   _  __ _ _ __ __| | |_ _|_ __ (_) |_ 
 \ \ /\ / /| |  __/ _ \ |  _| | | |/ _  |  __/ _  |  | ||  _ \| | __|
  \ V  V / | | | |  __/ |_| | |_| | (_| | | | (_| |  | || | | | | |_ 
   \_/\_/  |_|_|  \___|\____|\__,_|\__,_|_|  \__,_| |___|_| |_|_|\__|
   
"

	echo -e "$banner"
	echo -e "${CYAN}######################################################${NC}"
	echo -e "${CYAN}#                                                    #${NC}"
	echo -e "${CYAN}#                                                    #${NC}"
	echo -e "${CYAN}#                 ${GREEN}Welcome to wg_init!${CYAN}                #${NC}"
	echo -e "${CYAN}#                                                    #${NC}"
	echo -e "${CYAN}#           ${GREEN}This script helps automate the${CYAN}           #${NC}"
	echo -e "${CYAN}#      ${GREEN}process of setting up a WireGuard server${CYAN}      #${NC}"
	echo -e "${CYAN}#                  ${GREEN}and adding peers!${CYAN}                 #${NC}"
	echo -e "${CYAN}#                                                    #${NC}"
	echo -e "${CYAN}#                ${GREEN}Author: Chris Bratti${CYAN}                #${NC}"
	echo -e "${CYAN}#                                                    #${NC}"
	echo -e "${CYAN}######################################################${NC}"

	# Script needs to be run as root, so checks permissions before running
	if [ "$EUID" -ne 0 ]; then
		echo -e "${RED}This script requires root permissions, please run with sudo${NC}"
		exit
	fi

}

# Function to get user input and validate against a given regex pattern
get_user_input() {
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
get_binary_user_input() {
	local answer=$(get_user_input "$1(y/n)" $binaryOptionRegex)
	answer=$(echo $answer | tr '[:upper:]' '[:lower:]')
	if [[ "$answer" = 'y' || "$answer" = "yes" ]]; then
		return 0
	else
		return 1
	fi
}

# Displays small spinner to show a process running
spinner() {
	local pid=$!
	local delay=0.1
	local spinstr='|/-\'
	while [ "$(ps a | awk '{print $1}' | grep "$pid")" ]; do
		local temp=${spinstr#?}
		printf " [%c]  " "$spinstr"
		local spinstr=$temp${spinstr%"$temp"}
		sleep $delay
		printf "\b\b\b\b\b\b"
	done
	printf "    \b\b\b\b"
}

# Checks peer's connection to server
check_connection() {
	retryLimit=5
	retries=0
	# Checks the wireguard output for "latest handshake" to verify if handshake has been made.
	# Retries until the retryLimit is reached
	for ((retries = 0; retries <= $retryLimit; retries++)); do
		if sudo wg | grep -q "latest handshake"; then
			return 0
		fi
		sleep 1
	done

	return 1
}

# Prints out info message
info_message() {
	echo -e "${CYAN}$1${NC}" >&2
}

# Prints out success message
success_message() {
	echo -e "${GREEN}$1${NC}" >&2
}

# Prints out error message
error_message() {
	echo -e "${RED}$1${NC}" >&2
}

# Validates peer configuration file before processing it
validate_config_file() {
	local configFile=$1
	# Checks if file exists
	if [ ! -f "$configFile" ]; then
		error_message "Error: Configuration file not found. Please check server script for instructions on running peer setup."
		exit 1
	fi

	# Checks if file seems to be a valid wireguard config
	if ! grep -q "\[Interface\]" "$configFile" || ! grep -q "\[Peer\]" "$configFile"; then
		error_message "Error: Configuration file seems to be malformed. Please check server script for instructions on running peer setup."
		exit 1
	fi

	# Makes sure wireguard path exists
	mkdir -p $configPath

	# Copies file to wg0.conf
	cp "$configFile" "$configPath/wg0.conf"
	echo "$configPath/wg0.conf"
}

# Configures wireguard to run automatically as a service
configure_wg_as_service() {
	info_message "Configuring WireGuard to run automatically...."
	sudo systemctl enable wg-quick@wg0.service >/dev/null
	sudo systemctl start wg-quick@wg0.service >/dev/null

	# Checks to make sure WireGuard is running
	if systemctl is-active --quiet wg-quick@wg0.service; then
		success_message "WireGuard server is running!"
	else
		error_message "Error starting WireGuard server, please check logs"
		return 1
	fi
	info_message "✅ Done"
}

# Creates and initializes a new WireGuard client
init_client() {
	# Displays warning to user to let them know configuring machine as a peer will overwrite any
	#  existing configuration
	error_message "WARNING: This script will overwrite any existing wireguard configuration and configure this machine as a wireguard peer!"

	if ! get_binary_user_input "Continue with peer setup?"; then
		info_message "Aborting peer setup"
		exit 0
	fi

	if [[ -z $1 ]]; then
		error_message "No configuration file supplied"
		error_message "Usage: $0 init_client /path/to/config.conf"
		exit 1
	fi

	userConfFile="$1"
	shift

	while getopts "a" opt; do
		case $opt in
		a) autoRunWg=true ;;
		*)
			error_message "Invalid option for init_client"
			show_help
			exit 1
			;;
		esac
	done
	shift $((OPTIND - 1))

	# Validates config file
	info_message "Validating config file...."
	peerConfigFile=$(validate_config_file $userConfFile)
	info_message "✅ Done"

	info_message "Installing WireGuard...."
	sudo apt update -y >/dev/null

	sudo apt install wireguard -y >/dev/null

	sudo apt install resolvconf >/dev/null
	info_message "✅ Done"

	info_message "Configuring client traffic routing...."
	device=$(ip route list table main default | awk '{for(i=1;i<=NF;i++) if($i=="dev") print $(i+1)}')

	# If more than one network device, have user choose which network device to use
	[ $(echo $device | wc -w) -gt 1 ] && device=$(choose_net_device "$device")

	# Gets gateway address for client machine
	gatewayAddress=$(ip route list table main default | awk '{for(i=1;i<=NF;i++) if($i=="via") print $(i+1)}')

	# Gets internal ip address for network device
	ipAddress=$(ip -brief address show $device | awk '{for(i=1;i<=NF;i++) if($i=="UP") print $(i+1)}' | sed 's#/.*##')

	# Traffic routing rules to add to the wg0.conf file
	routeTrafficLines="PostUp = ip rule add from $ipAddress table main\nPostUp = ip route add default via $gatewayAddress table main\nPreDown = ip rule delete from $ipAddress table main\nPreDown = ip route delete default via $gatewayAddress table main"

	# Add traffic routing lines
	sed -i "/^Address = [0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\/[0-9]\{1,2\}$/a $routeTrafficLines" $peerConfigFile

	info_message "✅ Done"

	# Option to start wireguard by default
	$autoRunWg && configure_wg_as_service

	# Starts wireguard
	sudo wg-quick up wg0 >/dev/null

	# After wireguard is started, server script can continue
	success_message "Wireguard started!"
	info_message "Client setup is almost done! Make sure server script has finished and then press enter to continue"
	sleep 2
	read

	# Checks if client has made handshake with server
	info_message "Checking client connection..."
	if check_connection; then
		success_message "Client connected to VPN tunnel!"
		success_message "Client setup done!"
	else
		info_message "Setup is done, however"
		error_message "client is not currently connected to WireGuard server"
		info_message "Troubleshooting steps: "
		info_message "  1. Make sure ListenPort has been forwarded on the server's router"
		info_message "  2. Check that server is running"
		info_message "  3. Double check configuration file $peerConfigFile matches the one generated by the server script"
		info_message "  4. Double check any firewall rules that might be preventing the peer from connecting"
		info_message "  5. Run sudo wg to check wireguard status"
		return 1
	fi
}

# Given an ip, finds the next IP in that subnet
increment_ip() {
	echo "$1" | awk -F '[./]' '{ printf "%d.%d.%d.%d/%s\n", $1, $2, $3, $4+1, $5 }'
}

# Finds the next available IP using the wireguard config file
get_next_ip() {
	# Gets server address
	local serverAddress=$(grep "Address" $1/wg0.conf | cut -d "=" -f 2 | xargs | sed 's/\/.*/\/32/')

	# Finds the IP addresses already in use by other peers
	local usedIps=$(grep "AllowedIPs" "$1/wg0.conf" | sed 's/AllowedIPs = //')

	# Sets the nextIp to one higher than the server address
	local nextIp=$(increment_ip $serverAddress)

	# Increments nextIp until it finds one not in use by other peers
	while true; do
		if printf "%s\n" "${usedIps[@]}" | grep -q -x "$nextIp"; then
			nextIp=$(increment_ip $nextIp)
		else
			break
		fi
	done

	echo $nextIp
}

# Validates the user-supplied options
validate_peer_options() {

	if [[ -n $dnsAddress && ! $dnsAddress =~ $ipRegex ]]; then
		error_message "Invalid DNS Address format"
		dnsAddress=$(get_user_input "Enter valid DNS Address" $ipRegex)
	fi

	[ -z $peerName ] && read -p "Create name for new peer: " peerName

	local peerConfigPath="$configPath/wg-peers"
	mkdir -p $peerConfigPath

	# Each peer will have a unique config file based on a provided name
	while true; do
		if [ -f "$peerConfigPath/$peerName.conf" ]; then
			error_message "Peer config already exists, choose a different one"
			read -p "Create name for new peer: " peerName
		else
			newPeerPath="$peerConfigPath/$peerName.conf"
			break
		fi
	done
}

# Adds a peer to existing wireguard configuration
add_peer() {
	# Checks to make sure wireguard server has already been set up
	if [ ! -f $configPath/wg0.conf ]; then
		error_message "Could not add peer, WireGuard configuration not found"
		error_message "Generate one by running $0 init_server"
		exit 1
	fi

	while getopts "n:d:o:" opt; do
		case $opt in
		n) peerName="$OPTARG" ;;
		d) dnsAddress="$OPTARG" ;;
		o) configOption="$OPTARG" ;;
		*)
			echo "Invalid option for add_peer"
			exit 1
			;;
		esac
	done
	shift $((OPTIND - 1))

	newPeerPath=""

	validate_peer_options

	# Gets the next available IP in the address range
	nextIp=$(get_next_ip $configPath)

	# Gets server public key as well as server's public IP address
	publicKey=$(sudo cat $configPath/public.key)
	publicIp="$(curl --silent ifconfig.me)"

	info_message "Generating keys...."
	# Generates peer public and private keys
	peerPrivateKey=$(wg genkey)
	peerPublicKey=$(echo $peerPrivateKey | wg pubkey)

	info_message "✅ Done"

	# Gets the listen port from server config
	if [ -z $listenPort ]; then
		listenPort=$(sudo grep "ListenPort" $configPath/wg0.conf | cut -d "=" -f 2 | xargs)
	fi

	# Creates the new peer configuration file
	cat <<EOF >$newPeerPath
[Interface]
Address = $nextIp
PrivateKey = $peerPrivateKey
EOF
	[ -n "$dnsAddress" ] && echo "DNS = $dnsAddress" >>$newPeerPath
	cat <<EOF >>$newPeerPath

[Peer]
PublicKey = $publicKey
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = $publicIp:$listenPort
EOF

	info_message "✅ Peer configuration generated"

	if [[ -z $configOption ]]; then
		# Gives the user a choice in how they would like to set up their client
		info_message "Choose an option to configure client:"
		echo -e "${GREEN}1.${CYAN} QR code - great for mobile clients${NC}"
		echo -e "${GREEN}2.${CYAN} Client automation script - good to automate CLI clients${NC}"
		echo -e "${GREEN}2.${CYAN} Copy config file - Manually copy values from the config file to client${NC}"
		configOption=$(get_user_input "Choose an option" "^[1-3]{1}$")
	fi

	case $configOption in
	1)
		setup_mobile_client $newPeerPath
		;;
	2)
		client_script_config $newPeerPath
		;;
	3)
		manual_client_cetup $newPeerPath
		;;
	*)
		manual_client_cetup $newPeerPath
		;;
	esac

	info_message "Client configuration is located at $newPeerPath"

	# Adds the new peer to the WireGuard server
	info_message "Adding peer to server configuration...."
	sudo wg set wg0 peer $peerPublicKey allowed-ips $(echo "$nextIp" | sed 's/\/.*//')

	# Restarts wireguard server to load peer config
	sudo wg-quick down wg0 && sudo wg-quick up wg0
	info_message "✅ Done"

	# Checks server config for new peer to make sure it was added correctly
	if grep -q "$peerPublicKey" "$configPath/wg0.conf"; then
		success_message "Peer added successfully!"
	else
		error_message "Error adding peer, please try again"
	fi
}

# Used for manual client setup, displays client config file for users to copy
manual_client_cetup() {
	info_message "Config file located at $1"
	sudo cat $1
	echo -e "${GREEN}Press enter to proceed${NC}"
	read
}

# Generates QR code from peer config file - useful for mobile devices
setup_mobile_client() {
	qrencode -t ansiutf8 <$1
	echo -e "${GREEN}Use QR code to set up mobile device, then press enter when done${NC}"
	read
}

# Gives instructions on running the init_wg_client.sh script on client machine
client_script_config() {
	cat <<EOF
##################################################################
#  For automated peer setup, you will need access to the         #
#   peer machine. This script can be re-used to configure the    #
#   client machine as a peer.                                    #
#                                                                #
#   1. Copy the configuration file from below onto the client    #
#      machine.                                                  #
#   2. Run the commands below to pull down this script and       #
#      execute the init_client flow                              #
#                                                                #
#  wget $clientScriptLocation
#  chmod +x init_wg_client.sh                                    #
#  sudo ./init_wireguard.sh init_client /path/to/peerConfig.conf #
##################################################################
EOF
	info_message "#############Config File#############"
	cat $1
	info_message "After copying above config to client machine, press enter"
	read
}

# If a user has multiple network devices, allows them to choose which one to configure
choose_net_device() {
	local deviceString=$1
	local devicesArray=($deviceString)
	local chosenDevice=""
	info_message "More than one network device was detected on your system:"

	# Prints list of devices found
	for netDevice in "${devicesArray[@]}"; do
		info_message "$netDevice"
	done

	# Loop for users to choose device. Double checks that chosen device is a valid choice from device list
	info_message "You will need to choose which device you want the WireGuard server listening on"
	while true; do
		chosenDevice=$(get_user_input "Enter network device name" ".+")
		if printf "%s\n" "${devicesArray[@]}" | grep -q -x "$chosenDevice"; then
			echo $chosenDevice
			break
		else
			error_message "Unknown device, please choose one from the list of devices above"
		fi
	done

}

# Configures port forwarding to allow for full network sharing
configure_port_forwarding() {
	# Adds forwarding rule to systctl
	sudo sed -i '/^#*net\.ipv4\.ip_forward=1/s/^#//' /etc/sysctl.conf
	info_message "Enabling network forwarding..."

	# TODO: check output to confirm rule was added
	sudo sysctl -p >/dev/null

	info_message "✅ Done"

	info_message "Configuring iptables..."
	# Gets default network device
	device=$(ip route list default | awk '{for(i=1;i<=NF;i++) if($i=="dev") print $(i+1)}')

	# If more than one network device, have user choose which network device to use
	[ $(echo $device | wc -w) -gt 1 ] && device=$(choose_net_device "$device")

	# UFW rules to add to wireguard configuration file
	portForwardingLines="PostUp = ufw route allow in on wg0 out on $device\nPostUp = iptables -t nat -I POSTROUTING -o $device -j MASQUERADE\nPostUp = ip6tables -t nat -I POSTROUTING -o $device -j MASQUERADE\nPreDown = ufw route delete allow in on wg0 out on $device\nPreDown = iptables -t nat -D POSTROUTING -o $device -j MASQUERADE\nPreDown = ip6tables -t nat -D POSTROUTING -o $device -j MASQUERADE"

	# Adds rules to conf file, in the [Interface] block
	sed -i "/SaveConfig = true/a $portForwardingLines" $configPath/wg0.conf

	info_message "✅ Done"

	# Opens up listen port on wireguard server
	info_message "Enabling firewall ports..."
	sudo ufw allow $listenPort/udp >/dev/null
	sudo ufw allow OpenSSH >/dev/null

	# Restarts the ufw service
	sudo ufw disable >/dev/null
	sudo ufw enable

	info_message "✅ Done"

	# Checks ufw status to make sure listenPort was added correctly
	if sudo ufw status | grep -q "$listenPort/udp"; then
		success_message "Firewall rules updated!"
		sleep 2
	else
		error_message "Error enabling ufw"
		exit 1
	fi
}

validate_server_options() {

	[ -z $subnetRange ] && subnetRange="10.10.10.1/24"

	if [[ ! $subnetRange =~ $ipRangeRegex ]]; then
		error_message "IP range is not valid"
		subnetRange=$(get_user_input "Enter a valid IP Range" $ipRangeRegex)
	fi

	info_message "✅ Address range set"

	[ -z $listenPort ] && listenPort="51820"

	if [[! $listenPort =~ "[0-9]+" ]]; then
		error_message "ListenPort is not valid"
		listenPort=$(get_user_input "Enter a valid ListenPort" "[0-9]+")
	fi

	info_message "✅ ListenPort set"
}

# Creates and initializes a new WireGuard server
init_wireguard_server() {
	error_message "WARNING: This script will overwrite any existing wireguard configuration and configure this machine as a wireguard server!"
	if ! get_binary_user_input "Continue with server setup?"; then
		info_message "Aborting server setup"
		exit 0
	fi
	subnetRange=""
	listenPort=""

	while getopts "i:p:" opt; do
		case $opt in
		i) subnetRange="$OPTARG" ;;
		p) listenPort="$OPTARG" ;;
		*)
			echo "Invalid option for init_server"
			exit 1
			;;
		esac
	done
	shift $((OPTIND - 1))

	validate_server_options

	# Updates and installs Wireguard
	info_message "Updating and installing wireguard...."
	apt update -y >/dev/null

	apt install wireguard -y >/dev/null

	# Used for generating QR codes
	apt install qrencode -y >/dev/null

	info_message "✅ Done"

	# Creates private and public keys
	info_message "Generating keys...."
	umask 077 && sudo wg genkey >"$configPath/private.key"

	sudo chmod go= $configPath/private.key

	sudo cat $configPath/private.key | wg pubkey >$configPath/public.key

	info_message "✅ Done"

	privateKey=$(sudo cat $configPath/private.key)

	# Generates the wireguard configuration file
	info_message "Generating wireguard config...."
	cat <<EOF >$configPath/wg0.conf
[Interface]
PrivateKey = $privateKey
Address = $subnetRange
ListenPort = $listenPort
SaveConfig = true
EOF

	success_message "✅ WireGuard configuration generated:"
	sudo cat $configPath/wg0.conf
	sleep 2

	# Configures network forwarding rules
	configure_port_forwarding

	# Starts the wireguard server and enables to service so it auto-starts
	configure_wg_as_service

	# Gives user option to add new peer
	if get_binary_user_input "Add new peer?"; then
		add_peer
	else
		info_message "New peers can be added later by running $0 add_peer"
	fi

	info_message "########################################################"
	echo -e "${CYAN}# ${GREEN}Your WireGuard server has been created successfully! ${CYAN}#"
	info_message "#                                                      #"
	echo -e "${CYAN}# ${RED}You will need to forward port $listenPort on               ${CYAN}#"
	echo -e "${CYAN}#  ${RED}your router                                         ${CYAN}#"
	info_message "#                                                      #"
	info_message "# Your server won't be accessible remotely without it  #"
	info_message "#                                                      #"
	info_message "# This process varies between router brands, check     #"
	info_message "#  your router's configuration on these steps          #"
	info_message "#                                                      #"
	info_message "# Additional peers can be added using the 'add_peer'   #"
	info_message "#  option:                                             #"
	info_message "#   $0 add_peer"
	info_message "########################################################"

}

# Shows help message
show_help() {
	info_message "Usage: $0 <command> <options>"
	info_message "Commands:"
	success_message "  init_server - Creates a WireGuard server"
	info_message "      Arguments (Optional):"
	info_message "        -i <x.x.x.1/x>: Internal IP range for WireGuard network (ex. 10.0.0.1/24)"
	info_message "        -p <x>: Port that WireGuard will listen on (Default 51820)"
	echo ""
	success_message "  init_client - Configures a machine to be a wireguard peer"
	info_message "      Arguments (Optional):"
	info_message "        -a: Flag to configure WireGuard to autorun"
	echo ""
	success_message "  add_peer - Adds a new peer to an already existing server"
	info_message "      Arguments (Optional):"
	info_message "        -n <name>: Name for new peer"
	info_message "        -d <x.x.x.x>: DNS Address for peer to use"
	info_message "        -o <#>: Peer configuration option. One of:"
	info_message "                1. QR Code"
	info_message "                2. Client automation script"
	info_message "                3. Manual setup"
	echo ""
	success_message "  help - Shows this help messasge!"
}

scriptPath="$(
	cd -- "$(dirname "$0")" >/dev/null 2>&1
	pwd -P
)"
# Regex for validating user input
binaryOptionRegex="^[yYnN]$"
ipRegex="^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)"
ipRangeRegex="$ipRegex(\/(3[0-2]|[12]?[0-9]))?$"
# Script location
clientScriptLocation="https://raw.githubusercontent.com/chris-bratti/wireguard-init/refs/heads/master/init_wireguard.sh"

configPath="/etc/wireguard"
# Text colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

print_banner

if [[ $# -lt 1 ]]; then
	error_message "Error: No command provided."
	show_help
	exit 1
fi

command=$1
shift

case "$command" in
init_server)
	init_wireguard_server "$@"
	;;
init_client)
	init_client "$@"
	;;
add_peer)
	add_peer
	;;
help)
	show_help
	;;
*)
	error_message "Error: Unknown command '$command'"
	show_help
	exit 1
	;;
esac
