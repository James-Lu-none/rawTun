#!/bin/bash
set -euo pipefail

if [ "$EUID" -ne 0 ]; then
    echo "Run setup_network.sh as root." >&2
    exit 1
fi
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# defualt
TUN_DEV=tun0
TUN_IP=10.9.0.1
TUN_MASK=24

while IFS= read -r line || [[ -n "$line" ]]; do
    line=${line%%#*}
    [[ "$line" == *=* ]] || continue
    key=${line%%=*}
    value=${line#*=}
    key=${key//[[:space:]]/}
    value=${value//[[:space:]]/}
    case "$key" in
        SERVER_TUN_DEV) TUN_DEV=$value ;;
        SERVER_TUN_IP) TUN_IP=$value ;;
        SERVER_TUN_MASK) TUN_MASK=$value ;;
    esac
done < "$DIR/tunnel.conf"

if [[ ! "$TUN_DEV" =~ ^[a-zA-Z0-9_.-]+$ ]] ||
   [[ ! "$TUN_IP" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] ||
   [[ ! "$TUN_MASK" =~ ^[0-9]{1,2}$ ]] || (( 10#$TUN_MASK > 32 )); then
    echo "Set SERVER_TUN_DEV (e.g. tun0), SERVER_TUN_IP and SERVER_TUN_MASK in tunnel.conf." >&2
    exit 1
fi
# iptables normalizes the address/prefix to a network; no subnet calculation needed.
SUBNET="$TUN_IP/$TUN_MASK"
WAN_IF=$(ip -4 route get 1.1.1.1 | awk '{for (i=1; i<NF; i++) if ($i=="dev") {print $(i+1); exit}}')
if [[ ! "$WAN_IF" =~ ^[a-zA-Z0-9_.:-]+$ ]]; then
    echo "Cannot determine IPv4 internet interface." >&2
    exit 1
fi

sysctl -w net.ipv4.ip_forward=1
iptables -t nat -C POSTROUTING -s "$SUBNET" -o "$WAN_IF" -j MASQUERADE 2>/dev/null ||
    iptables -t nat -A POSTROUTING -s "$SUBNET" -o "$WAN_IF" -j MASQUERADE
iptables -C FORWARD -i "$TUN_DEV" -o "$WAN_IF" -s "$SUBNET" -j ACCEPT 2>/dev/null ||
    iptables -I FORWARD 1 -i "$TUN_DEV" -o "$WAN_IF" -s "$SUBNET" -j ACCEPT
iptables -C FORWARD -i "$WAN_IF" -o "$TUN_DEV" -d "$SUBNET" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT 2>/dev/null ||
    iptables -I FORWARD 1 -i "$WAN_IF" -o "$TUN_DEV" -d "$SUBNET" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

echo "[INFO] Forwarding/NAT ready: $TUN_DEV ($SUBNET) via $WAN_IF"
