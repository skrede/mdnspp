#!/bin/sh
set -eu

if [ $# -ne 1 ]; then
    echo "usage: $0 <build-dir>" >&2
    exit 2
fi

if [ -z "${MDNSPP_NETNS_OUTER_MNT:-}" ]; then
    MDNSPP_NETNS_OUTER_MNT=$(readlink /proc/self/ns/mnt)
    export MDNSPP_NETNS_OUTER_MNT
    script=$(cd "$(dirname "$0")" && pwd)/$(basename "$0")
    build_dir=$(cd "$1" && pwd)
    if [ "$(id -u)" -eq 0 ]; then
        exec unshare -nm --propagation private "$script" "$build_dir"
    fi
    exec unshare -rnm --propagation private "$script" "$build_dir"
fi
build_dir=$1

# ip netns keeps its namespaces under /run/netns; the tmpfs hides the host's /run only inside this mount namespace.
if [ "$(readlink /proc/self/ns/mnt)" = "$MDNSPP_NETNS_OUTER_MNT" ]; then
    echo "refusing to mount over /run outside a private mount namespace" >&2
    exit 1
fi
mount -t tmpfs none /run

for ns in dut p0 p1; do
    ip netns add "$ns"
    ip netns exec "$ns" sh -c 'for c in all default; do echo 0 > /proc/sys/net/ipv6/conf/$c/accept_dad; done'
    ip -n "$ns" link set lo up
done

ip -n dut link add d0 type veth peer name q0 netns p0
ip -n dut link add d1 type veth peer name q1 netns p1

link_up() {
    ip -n "$1" addr add "$3/24" dev "$2"
    ip -n "$1" addr add "$4/64" dev "$2" nodad
    ip -n "$1" link set "$2" up
}
link_up dut d0 10.20.0.1 fd20:0::1
link_up p0 q0 10.20.0.2 fd20:0::2
link_up dut d1 10.20.1.1 fd20:1::1
link_up p1 q1 10.20.1.2 fd20:1::2
# Sixteen more sources per family on q0: the kernel hands a unicast datagram to one socket of a shared port by a hash
# that includes the source address. A deprecated IPv6 address is never chosen as a default source.
for n in $(seq 100 115); do
    ip -n p0 addr add "10.20.0.$n/24" dev q0
    ip -n p0 addr add "fd20:0::$n/64" dev q0 nodad preferred_lft 0
done
# The kernel reports a veth carrier asynchronously, and IPv6 enables a link only once it has one.
ipv6_ready() {
    ip -n "$1" -6 route show table local dev "$2" | grep -q '^multicast ff00::/8'
}
for link in "dut d0" "dut d1" "p0 q0" "p1 q1"; do
    tries=0
    until ipv6_ready $link; do
        tries=$((tries + 1))
        [ "$tries" -le 50 ] || { echo "IPv6 did not come up on $link" >&2; exit 1; }
        sleep 0.1
    done
done

ip -n dut route add default via 10.20.1.2 dev d1
ip -n dut -6 route add default via fd20:1::2 dev d1

for link in l0 l1; do
    ip -n dut link add "$link" type dummy
    ip -n dut link set "$link" addrgenmode none
    ip -n dut link set "$link" multicast on
    ip -n dut addr add fe80::20/64 dev "$link" nodad
    ip -n dut link set "$link" up
done

exec ip netns exec dut env MDNSPP_REQUIRE_NETNS=1 \
    ctest --test-dir "$build_dir" -L netns --no-tests=error --output-on-failure --timeout 120
