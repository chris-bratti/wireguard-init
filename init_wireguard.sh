#!/bin/bash

print_banner () {
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

	if [ "$EUID" -ne 0 ];then 
		echo -e "${RED}This script requires root permissions, please run with sudo${NC}"
  		exit
	fi

}

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

get_binary_user_input () {
	local answer=$(get_user_input "$1(y/n)" $binaryOptionRegex)
	answer=$(echo $answer | tr '[:upper:]' '[:lower:]')
	if [[ "$answer" = 'y' || "$answer" = "yes" ]]; then
		return 0
	else
		return 1
	fi
}

increment_ip () {
	ipRange=$1
	subnetOctets=$(echo "$ipRange" | cut -d '.' -f 1-3)
	lastOctet=$(echo "$ipRange" | sed 's/^.*\.//;s/\/.*$//')
	subnet=$(echo "$ipRange" | sed 's/^.*\///')

	incrementedOctet=$((lastOctet + 1))

	nextIp="$subnetOctets.$incrementedOctet/$subnet"

	echo "$nextIp"
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

ip_to_int () {
    local ip="$1"
    IFS='.' read -r i1 i2 i3 i4 <<< "$ip"
    #echo $(( ( i1 << 24 ) + ( i2 << 16 ) + ( i3 << 8 ) + i4 ))
}

add_peer () {
	if [ ! -f $configPath/wg0.conf]; then
		error_message "Could not add peer, WireGuard configuration not found"
		error_message "Generate one by running $0 init_server"
		return 1
	fi
	peerConfigPath="$configPath/wg-peers"
	mkdir -p $peerConfigPath
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

	if [ -z "$highestIp" ]; then
		highestIp="$subnetRange"
	else
		subnet=$(echo "$subnetRange" | sed 's/^.*\///')
		highestIp="$highestIp/$subnet"
	fi

	publicKey=$(sudo cat $configPath/public.key)
	publicIp="$(curl --silent ifconfig.me)"

	nextIp=$(increment_ip "$highestIp")

	newPeerPath=""


	while true; do
		read -p "Create name for new peer: " peerName
		if [ -f "$peerConfigPath/$peerName.conf" ]; then
    		error_message "Peer config already exists, choose a different one"
		else
			newPeerPath="$peerConfigPath/$peerName.conf"
			break
		fi
	done
	

	peerPrivateKey=$(wg genkey)
	peerPublicKey=$(echo $peerPrivateKey | wg pubkey)

	if get_binary_user_input "Use custom DNS address?"; then
		dnsAddress="$(get_user_input "DNS address" $ipRegex)"
	fi

	if [ -z $listenPort ]; then
		listenPort=$(sudo grep "ListenPort" $configPath/wg0.conf | cut -d "=" -f 2 | xargs)
	fi

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

	info_message "Choose an option to configure client:"
	echo -e "${GREEN}1.${CYAN} QR code - great for mobile clients${NC}"
	echo -e "${GREEN}2.${CYAN} Copy config file - good for CLI clients${NC}"
	
	configOption=$(get_user_input "Choose an option" "^[1-2]{1}$")

	case $configOption in
		1)
			setup_mobile_client $newPeerPath
			;;
		2)
			setup_client_config $newPeerPath
			;;
		*)
			setup_client_config $newPeerPath
			;;
	esac

	info_message "Client configuration is located at $newPeerPath"

	info_message "Adding peer to server configuration...."
	sudo wg set wg0 peer $peerPublicKey allowed-ips $(echo "$nextIp" | sed 's/\/.*//')

	sudo wg-quick down wg0 && sudo wg-quick up wg0

	if grep -q "$peerPublicKey" "$configPath/wg0.conf"; then
		success_message "Peer added successfully!"
	else
		error_message "Error adding peer, please try again"
	fi
}


setup_client_config (){
	info_message "Config file located at $1"
	sudo cat $1
	echo -e "${GREEN}Press enter to proceed${NC}"
	read
}


setup_mobile_client (){
	qrencode -t ansiutf8 < $1
	echo -e "${GREEN}Use QR code to set up mobile device, then press enter when done${NC}"
	read
}

client_script_instructions (){

cat << EOF
##########################################################
#  For automated peer setup, you will need access to the #
#	peer machine. There is a companion script to 		 #
#	configure the client machine as a peer. 			 #
# 														 #
# Run the following commands on the peer machine and     #
#	follow the script instructions:						 #
#														 #
# wget $clientScriptLocation							
# chmod +x init_wg_client.sh							 #
# sudo ./init_wg_client.sh $nextIp $publicIp:$listenPort
#														 #
# When the script prompts for a public key, enter:       #
# $publicKey										    
#													     #
# Then enter the public key that the script outputs		 #
##########################################################
EOF
	read -p "Enter public key from peer script: " peerPublicKey
}

configure_port_forwarding (){
	if ! grep -q "net.ipv4.ip_forward=1" "/etc/sysctl.conf"; then
		echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
	fi

	info_message "Enabling network forwarding..."

	sudo sysctl -p

# TODO: check for multiple devices before continuing
	info_message "Configuring iptables..."
	device=$(ip route list default | awk '{for(i=1;i<=NF;i++) if($i=="dev") print $(i+1)}')

	if [ $(echo $device |  wc -w) -gt 1 ]; then
        echo "More than one"
	fi

	portForwadingLines="PostUp = ufw route allow in on wg0 out on $device\nPostUp = iptables -t nat -I POSTROUTING -o $device -j MASQUERADE\nPostUp = ip6tables -t nat -I POSTROUTING -o $device -j MASQUERADE\nPreDown = ufw route delete allow in on wg0 out on $device\nPreDown = iptables -t nat -D POSTROUTING -o $device -j MASQUERADE\nPreDown = ip6tables -t nat -D POSTROUTING -o $device -j MASQUERADE"
	
	sudo sed -i "/SaveConfig = true/a $portForwardingLines" $configPath/wg0.conf

	info_message "Enabling firewall ports..."
	sudo ufw allow $listenPort/udp
	sudo ufw allow OpenSSH


	sudo ufw disable
	sudo ufw enable

	if sudo ufw status | grep -q "$listenPort/udp"; then
		success_message "Firewall rules updated"
	else
		error_message "Error enabling ufw"
		exit 1
	fi
}

init_wireguard_server (){

	info_message "Updating..."
	apt update -y > /dev/null

	info_message "Installing wireguard..."
	apt install wireguard -y > /dev/null

	apt install qrencode -y

	info_message "Generating private key..."
	wg genkey | sudo tee $configPath/private.key

	sudo chmod go= $configPath/private.key

	info_message "Generating public key..."
	sudo cat $configPath/private.key | wg pubkey | sudo tee $configPath/public.key

	if get_binary_user_input "Change default wireguard address range from 10.10.10.1/24?"; then
cat << EOF
###########################################################
# The WireGuard address range is used for WireGuard peers #
#  to communicate with each other			  #
# You must use an internal IP address range               #
# Valid internal IP ranges are:				  #
#							  #
#    10.0.0.0 to 10.255.255.255				  #
#    172.16.0.0 to 172.31.255.255		          #
#    192.168.0.0 to 192.168.255.255			  #
#							  #
# Enter IP in format xxx.xxx.xxx.xxx/xx			  #
# Example: 192.168.1.1/24				  #
# Where 24 is the IP subnet				  #
###########################################################
EOF

		subnetRange=$(get_user_input "Enter an IP Range" $ipRangeRegex)
	else
		subnetRange="10.10.10.1/24"
	fi

	if get_binary_user_input "Change default ListenPort from 51820?"; then
cat << EOF
###########################################################
# The ListenPort determines the UDP port clients will use #
#  to connect to the WireGuard server.                    #
#							  							  #
# Try not to use common ports like 8080, 22, 80, etc, as  #
#  you might run into port conflicts			          #
#                                                         #
# The port you choose will also need to be forwarded on   #
#  your router (we will cover that later)                 #
###########################################################
EOF
		listenPort=$(get_user_input "Enter a ListenPort" "[0-9]+")
	else
		listenPort="51820"
	fi

	privateKey=$(sudo cat $configPath/private.key)

	info_message "Generating wireguard config...."
cat <<EOF > $configPath/wg0.conf
[Interface]
PrivateKey = $privateKey
Address = $subnetRange
ListenPort = $listenPort
SaveConfig = true
EOF

	success_message "WireGuard configuration generated:"
	sudo cat $configPath/wg0.conf
	sleep 3

	configure_port_forwarding

	info_message "Starting Wireguard server...."
	sudo systemctl enable wg-quick@wg0.service
	sudo systemctl start wg-quick@wg0.service

	if systemctl is-active --quiet wg-quick@wg0.service; then
		success_message "WireGuard server is running!"
	else
		error_message "Error starting WireGuard server, please check logs"
		return 1
	fi

	if get_binary_user_input "Add new peer?"; then
		add_peer
	else
		info_message "New peers can be added later by running $0 add_peer"
	fi

	info_message "########################################################"
	echo -e "${CYAN}# ${GREEN}Your WireGuard server has been created successfully! ${CYAN}#"
	info_message "#                                                      #"
	echo -e "${CYAN}# ${RED}You will need to forward port $listenPort on           ${CYAN}#"
	echo -e "${CYAN}#  ${RED}on your router                                        ${CYAN}#"
	info_message "# Your server won't be accessible remotely without it  #"
	info_message "# This process varies between router brands, check     #"
	info_message "#  your router's configuration on these steps          #"
	info_message "#                                                      #"
	info_message "# Additional peers can be added using the 'add_peer'   #"
	info_message "#  option:                                             #"
	info_message "#   $0 add_peer"
	info_message "########################################################"

}

show_help (){
	info_message "This script is used to automate the creation of a Wireguard server"
	info_message "Usage: $0 <command>"
	info_message "Commands:"
	success_message "  init_server       Creates a WireGuard server"
	success_message "  add_peer          Adds a new peer to an already existing server"
	success_message "  help              Shows this help messasge!"

}

scriptPath="$( cd -- "$(dirname "$0")" >/dev/null 2>&1 ; pwd -P )"
binaryOptionRegex="^[yYnN]$"
ipRegex="^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)"
ipRangeRegex="$ipRegex(\/(3[0-2]|[12]?[0-9]))?$"
clientScriptLocation="www.github.com/path/here/blah"
configPath="/etc/wireguard"
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

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

