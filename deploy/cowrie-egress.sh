#!/usr/bin/env bash
# Keep the Cowrie container away from your own network.
#
# Cowrie's wget/curl already refuse private addresses, but the CONTAINER can still reach the
# LAN, the Docker gateway and this machine's own services. If something ever escaped Cowrie,
# that is where it would go next. This blocks the container from private ranges and from this
# host, while leaving the internet open (Cowrie's `wget` of a payload still works).
#
#   sudo deploy/cowrie-egress.sh            # add the rules
#   sudo deploy/cowrie-egress.sh --remove   # take them out
#   sudo deploy/cowrie-egress.sh --check    # show what is in place
#
# Rules are not saved across a reboot: run it again afterwards (or put it in a unit).
set -euo pipefail
NET="${COWRIE_NETWORK:-honeypot_default}"
CHAIN=HYDRAPOT-EGRESS
SUBNET="$(docker network inspect "$NET" --format '{{(index .IPAM.Config 0).Subnet}}')"
PRIVATE="10.0.0.0/8 172.16.0.0/12 192.168.0.0/16 169.254.0.0/16 100.64.0.0/10"

remove() {
  iptables -D DOCKER-USER -s "$SUBNET" -j "$CHAIN" 2>/dev/null || true
  iptables -D INPUT -s "$SUBNET" -m conntrack --ctstate NEW -j DROP 2>/dev/null || true
  iptables -F "$CHAIN" 2>/dev/null || true
  iptables -X "$CHAIN" 2>/dev/null || true
}

case "${1:-}" in
  --remove) remove; echo "removed"; exit 0 ;;
  --check)  iptables -S "$CHAIN" 2>/dev/null || echo "no $CHAIN chain"
            iptables -S DOCKER-USER | grep "$CHAIN" || echo "not hooked into DOCKER-USER"
            iptables -S INPUT | grep "$SUBNET" || echo "no INPUT rule for $SUBNET"; exit 0 ;;
esac

remove
iptables -N "$CHAIN"
for range in $PRIVATE; do iptables -A "$CHAIN" -d "$range" -j DROP; done
iptables -A "$CHAIN" -j RETURN
iptables -I DOCKER-USER -s "$SUBNET" -j "$CHAIN"
# connections the container starts towards this machine itself (replies to ours are ESTABLISHED)
iptables -I INPUT -s "$SUBNET" -m conntrack --ctstate NEW -j DROP
echo "Cowrie ($SUBNET) can no longer reach $PRIVATE or this host."
echo "Check:  docker exec $(docker ps --filter network=$NET --format '{{.Names}}' | head -1) /cowrie/cowrie-env/bin/python -c \"import urllib.request as u; u.urlopen('http://${GATEWAY_PROBE:-172.17.0.1}:1/', timeout=3)\""
