#!/bin/bash

# Prints welcome banner
print_banner () {
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
	if [ "$EUID" -ne 0 ];then 
		echo -e "${RED}This script requires root permissions, please run with sudo${NC}"
  		exit
	fi

}

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

# Given an ip, finds the next IP in that subnet
increment_ip () {
	ipRange=$1
	subnetOctets=$(echo "$ipRange" | cut -d '.' -f 1-3)
	lastOctet=$(echo "$ipRange" | sed 's/^.*\.//;s/\/.*$//')
	subnet=$(echo "$ipRange" | sed 's/^.*\///')

	incrementedOctet=$((lastOctet + 1))

	nextIp="$subnetOctets.$incrementedOctet/$subnet"

	echo "$nextIp"
}

# Prints out info message
info_message (){
	echo -e "${CYAN}$1${NC}" >&2
}

# Prints out success message
success_message (){
	echo -e "${GREEN}$1${NC}" >&2
}

# Prints out error message
error_message (){
	echo -e "${RED}$1${NC}" >&2
}

# Converts an IP to an integer so IPs can be compared
ip_to_int () {
    local ip="$1"
    IFS='.' read -r i1 i2 i3 i4 <<< "$ip"
    echo $(( ( i1 << 24 ) + ( i2 << 16 ) + ( i3 << 8 ) + i4 ))
}

# Adds a peer to existing wireguard configuration
add_peer () {
	# Checks to make sure wireguard server has already been set up
	if [ ! -f $configPath/wg0.conf ]; then
		error_message "Could not add peer, WireGuard configuration not found"
		error_message "Generate one by running $0 init_server"
		return 1
	fi

	peerConfigPath="$configPath/wg-peers"
	mkdir -p $peerConfigPath

	# Finds the IP addresses already in use by other peers, and determines the highest one
	usedIps=$(grep "AllowedIPs" "$configPath/wg0.conf" | sed 's/AllowedIPs = //;s/\/.*//')
	highestIp=""
	
	if [ -z "$subnetRange" ]; then
		subnetRange=$(sudo grep "Address" $configPath/wg0.conf | cut -d "=" -f 2 | xargs)
	fi

	for ip in $usedIps; do
		ipAsInt=$(ip_to_int "$ip")
		if [[ -z "$highestIp" || $ipAsInt -gt $(ip_to_int "$highestIp") ]]; then
			highestIp="$ip"
		fi
	done

	# If no IPs were found, defaults to the subnet range in the server configuration
	if [ -z "$highestIp" ]; then
		highestIp="$subnetRange"
	else
		subnet=$(echo "$subnetRange" | sed 's/^.*\///')
		highestIp="$highestIp/$subnet"
	fi

	# Increments the highest found IP to determine the next available IP in the range
	nextIp=$(increment_ip "$highestIp")

	# Gets server public key as well as server's public IP address
	publicKey=$(sudo cat $configPath/public.key)
	publicIp="$(curl --silent ifconfig.me)"

	newPeerPath=""

	# Each peer will have a unique config file based on a provided name
	while true; do
		read -p "Create name for new peer: " peerName
		if [ -f "$peerConfigPath/$peerName.conf" ]; then
    		error_message "Peer config already exists, choose a different one"
		else
			newPeerPath="$peerConfigPath/$peerName.conf"
			break
		fi
	done
	
	info_message "Generating keys...."
	# Generates peer public and private keys
	peerPrivateKey=$(wg genkey)
	peerPublicKey=$(echo $peerPrivateKey | wg pubkey)

	info_message "✅ Done"

	# Users can provide a custom DNS address for the new peer to use
	if get_binary_user_input "Use custom DNS address?"; then
		dnsAddress="$(get_user_input "DNS address" $ipRegex)"
		info_message "✅ DNS Address set"
	fi

	# Gets the listen port from server config
	if [ -z $listenPort ]; then
		listenPort=$(sudo grep "ListenPort" $configPath/wg0.conf | cut -d "=" -f 2 | xargs)
	fi

	#TODO: Check before setting AllowedIPs

# Creates the new peer configuration file
cat << EOF > $newPeerPath
[Interface]
Address = $nextIp
PrivateKey = $peerPrivateKey
EOF
	if [[ -n "$dnsAddress" ]]; then
    	echo "DNS = $dnsAddress" >> $newPeerPath
	fi
cat << EOF >> $newPeerPath

[Peer]
PublicKey = $publicKey
AllowedIPs = 0.0.0.0/0
Endpoint = $publicIp:$listenPort
EOF

	info_message "✅ Peer configuration generated"

	# Gives the user a choice in how they would like to set up their client
	info_message "Choose an option to configure client:"
	echo -e "${GREEN}1.${CYAN} QR code - great for mobile clients${NC}"
	echo -e "${GREEN}2.${CYAN} Client companion script - good to automate CLI clients${NC}"
	echo -e "${GREEN}2.${CYAN} Copy config file - Manually copy values from the config file to client${NC}"
	
	configOption=$(get_user_input "Choose an option" "^[1-3]{1}$")

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
manual_client_cetup (){
	info_message "Config file located at $1"
	sudo cat $1
	echo -e "${GREEN}Press enter to proceed${NC}"
	read
}

# Generates QR code from peer config file - useful for mobile devices
setup_mobile_client (){
	qrencode -t ansiutf8 < $1
	echo -e "${GREEN}Use QR code to set up mobile device, then press enter when done${NC}"
	read
}

# Gives instructions on running the init_wg_client.sh script on client machine
client_script_config (){
	cat << EOF
##########################################################
#  For automated peer setup, you will need access to the #
#       peer machine. There is a companion script to     #
#       configure the client machine as a peer.          #
#                                                        #
# You will need to copy the peer configuration file from #
#  below onto the client machine and pass its location   #
#  as an argument to the script                          #
#                                                        #
# Run the following commands on the peer machine and     #
#       follow the script instructions:                  #
#                                                        #
# wget $clientScriptLocation
# chmod +x init_wg_client.sh                             #
# sudo ./init_wg_client.sh /path/to/peerConfig.conf      #
##########################################################
EOF
	info_message "#############Config File#############"
	cat $1
	info_message "When client setup is complete, press enter"
	read
}

# If a user has multiple network devices, allows them to choose which one to configure
choose_net_device (){
	local deviceString=$device
	devicesArray=($deviceString)
	info_message "More than one network device was detected on your system:"
	
	# Prints list of devices found
	for netDevice in "${devicesArray[@]}"
	do
		info_message "$netDevice"
	done

	# Loop for users to choose device. Double checks that chosen device is a valid choice from device list
	info_message "You will need to choose which device you want the WireGuard server listening on"
	while true; do   
		chosenDevice=$(get_user_input "Enter network device name" ".+")
		if printf "%s\n" "${devicesArray[@]}" | grep -q -x "$chosenDevice"; then
			device=$chosenDevice
			break
		else
			error_message "Unknown device, please choose one from the list of devices above"
		fi
	done

}

# Configures port forwarding to allow for full network sharing
configure_port_forwarding (){
	# Adds forwarding rule to systctl
	sudo sed -i '/^#*net\.ipv4\.ip_forward=1/s/^#//' /etc/sysctl.conf
	info_message "Enabling network forwarding..."

# TODO: check output to confirm rule was added
	sudo sysctl -p > /dev/null

	info_message "✅ Done"

	info_message "Configuring iptables..."
	# Gets default network device
	device=$(ip route list default | awk '{for(i=1;i<=NF;i++) if($i=="dev") print $(i+1)}')

	# If more than one network device, have user choose which network device to use
	if [ $(echo $device |  wc -w) -gt 1 ]; then
        choose_net_device
	fi

	# UFW rules to add to wireguard configuration file	
	portForwardingLines="PostUp = ufw route allow in on wg0 out on $device\nPostUp = iptables -t nat -I POSTROUTING -o $device -j MASQUERADE\nPostUp = ip6tables -t nat -I POSTROUTING -o $device -j MASQUERADE\nPreDown = ufw route delete allow in on wg0 out on $device\nPreDown = iptables -t nat -D POSTROUTING -o $device -j MASQUERADE\nPreDown = ip6tables -t nat -D POSTROUTING -o $device -j MASQUERADE"

	# Adds rules to conf file, in the [Interface] block
	sed -i "/SaveConfig = true/a $portForwardingLines" $configPath/wg0.conf

	info_message "✅ Done"

	# Opens up listen port on wireguard server
	info_message "Enabling firewall ports..."
	sudo ufw allow $listenPort/udp > /dev/null
	sudo ufw allow OpenSSH > /dev/null

	# Restarts the ufw service
	sudo ufw disable > /dev/null
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

# Creates and initializes a new WireGuard server
init_wireguard_server (){

	# Updates and installs Wireguard
	info_message "Updating...."
	apt update -y > /dev/null
	info_message "✅ Done"

	info_message "Installing wireguard...."
	apt install wireguard -y > /dev/null

	# Used for generating QR codes
	apt install qrencode -y > /dev/null

	info_message "✅ Done"

	# Creates private and public keys
	info_message "Generating keys...."
	wg genkey | sudo tee $configPath/private.key

	sudo chmod go= $configPath/private.key

	sudo cat $configPath/private.key | wg pubkey | sudo tee $configPath/public.key

	info_message "✅ Done"

	# Allows users to pick port range
	if get_binary_user_input "Change default wireguard address range from 10.10.10.1/24?"; then
cat << EOF
###########################################################
# The WireGuard address range is used for WireGuard peers #
#  to communicate with each other                         #
#                                                         #
# You must use an internal IP address range for this      #
# Valid internal IP ranges are:                           #
#                                                         #
#    10.0.0.0 to 10.255.255.255                           #
#    172.16.0.0 to 172.31.255.255                         #
#    192.168.0.0 to 192.168.255.255                       #
#                                                         #
# Enter IP in format xxx.xxx.xxx.1/xx                     #
# Example: 192.168.8.1/24                                 #
###########################################################
EOF

		subnetRange=$(get_user_input "Enter an IP Range" $ipRangeRegex)
	else
		subnetRange="10.10.10.1/24"
	fi

	info_message "✅ Address range set"

	# Allows users to change default Listen Port
	if get_binary_user_input "Change default ListenPort from 51820?"; then
cat << EOF
###########################################################
# The ListenPort determines the UDP port clients will use #
#  to connect to the WireGuard server.                    #
#                                                         #
# Try not to use common ports like 8080, 22, 80, etc, as  #
#  you might run into port conflicts                      #
#                                                         #
# The port you choose will also need to be forwarded on   #
#  your router (we will cover that later)                 #
###########################################################
EOF
		listenPort=$(get_user_input "Enter a ListenPort" "[0-9]+")
	else
		listenPort="51820"
	fi

	info_message "✅ ListenPort set"

	privateKey=$(sudo cat $configPath/private.key)

	# Generates the wireguard configuration file
	info_message "Generating wireguard config...."
cat <<EOF > $configPath/wg0.conf
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
	info_message "Starting Wireguard server...."
	sudo systemctl enable wg-quick@wg0.service
	sudo systemctl start wg-quick@wg0.service

	info_message "✅ Done"

	# Checks if wireguard server is running
	if systemctl is-active --quiet wg-quick@wg0.service; then
		success_message "✅ WireGuard server is running!"
	else
		error_message "Error starting WireGuard server, please check logs"
		return 1
	fi

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
show_help (){
	info_message "Usage: $0 <command>"
	info_message "Commands:"
	success_message "  init_server       Creates a WireGuard server"
	success_message "  add_peer          Adds a new peer to an already existing server"
	success_message "  help              Shows this help messasge!"

}

scriptPath="$( cd -- "$(dirname "$0")" >/dev/null 2>&1 ; pwd -P )"
# Regex for validating user input
binaryOptionRegex="^[yYnN]$"
ipRegex="^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)"
ipRangeRegex="$ipRegex(\/(3[0-2]|[12]?[0-9]))?$"
# Companion script location
clientScriptLocation="https://raw.githubusercontent.com/chris-bratti/wireguard-init/refs/heads/master/init_wg_client.sh"

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

case "$command" in
    init_server)
        init_wireguard_server
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

