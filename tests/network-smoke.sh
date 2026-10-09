#!/bin/sh
# Runs only in an isolated disposable Linux container with NET_ADMIN.
set -eu
apk add --no-cache nftables jq iproute2 qemu-mipsel >/dev/null
mkdir -p /tmp/routerbox /usr/local/bin
cat > /usr/local/bin/jsonfilter <<'SH'
#!/bin/sh
while [ "$#" -gt 0 ]; do
 case "$1" in -i) FILE=$2;shift 2;; -e) EXPR=$2;shift 2;; *)exit 1;;esac
done
EXPR=$(printf '%s' "$EXPR" | sed 's/^@//; s/\[\*\]/[]/g')
exec jq -r "$EXPR" "$FILE"
SH
chmod +x /usr/local/bin/jsonfilter
printf '%s\n' '{"enabled":true,"failure":"block","ipv6":false,"interfaces":["br-lan"]}' > /tmp/routerbox/network.json
sh /work/files/usr/lib/routerbox/network guard
nft list table inet routerbox_guard >/dev/null
printf 'nftables guard: OK\n'
ip link add br-lan type bridge
ip addr add 192.168.250.1/24 dev br-lan
ip link set br-lan up
cat > /tmp/core-smoke.json <<'JSON'
{"log":{"disabled":true},"inbounds":[{"type":"tun","tag":"tun","interface_name":"rb-tun","address":["172.31.255.1/30"],"mtu":1400,"stack":"system","auto_route":true,"auto_redirect":true,"include_interface":["br-lan"]}],"outbounds":[{"type":"direct","tag":"direct"}],"route":{"auto_detect_interface":true,"final":"direct"}}
JSON
/work/build/sing-box-linux-arm64 check -c /tmp/core-smoke.json
/work/build/sing-box-linux-arm64 run -c /tmp/core-smoke.json > /tmp/core.log 2>&1 &
CORE_PID=$!
trap 'kill "$CORE_PID" 2>/dev/null || true' EXIT
sleep 2
kill -0 "$CORE_PID"
ip link show rb-tun >/dev/null
printf 'TUN and auto_redirect: OK\n'
kill "$CORE_PID"
wait "$CORE_PID" || true
trap - EXIT
nft list table inet routerbox_guard >/dev/null
printf 'guard survives core exit: OK\n'
sh /work/files/usr/lib/routerbox/network stop
! nft list table inet routerbox_guard >/dev/null 2>&1
printf 'guard cleanup: OK\n'
qemu-mipsel /work/dist/routerbox-mipsle defaults | jq -e '.interfaces == ["br-lan"] and .storage == "flash"' >/dev/null
qemu-mipsel /work/dist/sing-box-mipsle version
printf 'MIPS softfloat executables: OK\n'
