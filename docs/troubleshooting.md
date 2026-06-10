# Troubleshooting

Practical diagnosis for the failure modes most commonly encountered when
deploying mDNS on real networks. Each section states the symptom, the cause,
and the remedy, with the mdnspp configuration that applies.

## Port 5353 is already in use

**Symptom:** socket construction throws `std::system_error` (or sets the
`std::error_code &` out-parameter) with an address-in-use error, or the peer
constructs but never receives multicast traffic.

mdnspp binds its sockets with `SO_REUSEADDR`, and additionally `SO_REUSEPORT`
where the platform defines it (Linux, macOS, BSD), so coexistence with another
mDNS responder bound to port 5353 generally works at the socket level. The
remaining problems are behavioral, not bind failures:

- **Windows — `Dnscache` service.** Windows 10 (1703+) and 11 run an mDNS
  responder inside the DNS Client service (`Dnscache`), bound to 5353. With
  `SO_REUSEADDR` the bind succeeds, but inbound unicast responses addressed
  to port 5353 may be delivered to only one of the bound sockets. Prefer
  multicast (QM) queries on Windows; QU responses and legacy unicast replies
  from other hosts can be consumed by the system responder instead of mdnspp.
- **Windows — Bonjour (`mDNSResponder`).** Installed by iTunes and several
  printer drivers. Same delivery caveat as `Dnscache`; additionally Bonjour
  answers queries for records it has registered, so observed traffic can
  include records mdnspp did not announce.
- **Linux — `avahi-daemon`.** Coexists at the socket level (both set
  `SO_REUSEPORT`), and the kernel fans inbound multicast out to every joined
  socket, so an mdnspp peer and Avahi observe the same traffic. Note that
  Avahi answers for the host (`<hostname>.local` A/AAAA): announcing the same
  hostname from mdnspp triggers probe conflicts — use a distinct `hostname`
  in `service_info`, or disable Avahi's publishing
  (`disable-publishing=yes` in `avahi-daemon.conf`).
- **macOS — `mDNSResponder`.** Always running and cannot be disabled in
  practice. Coexistence works through `SO_REUSEPORT`; the same QU/legacy
  unicast delivery caveat applies.

If another process bound 5353 *without* the reuse flags, mdnspp's bind fails
with `EADDRINUSE`. The error surfaces at peer construction (see
[Where errors surface](#where-errors-surface)).

## Same-host, multi-process discovery

**Symptom:** a server in one process is not discovered by a monitor or
discovery peer in another process on the same machine, while remote hosts
discover it fine.

Two conditions must hold for same-host discovery:

1. **All sockets share port 5353 with reuse flags.** mdnspp sets
   `SO_REUSEADDR` and (where available) `SO_REUSEPORT` on both
   `default_socket` and `asio_socket`, before `bind()`. `SO_REUSEPORT` is
   what guarantees inbound multicast fan-out to *every* joined socket on
   Linux; without it only one socket may receive each datagram. If you wrap a
   custom policy around your own socket, set both options before binding.
2. **Multicast loopback is enabled.** `socket_options::multicast_loopback`
   defaults to `loopback_mode::enabled`, which makes the kernel deliver
   multicast packets sent by one local socket back to other local sockets
   joined to the group (and to the sender itself). Setting
   `loopback_mode::disabled` reduces local traffic but makes same-host peers
   mutually invisible. Leave it enabled unless every consumer of your
   announcements is a remote host.

A server and a consumer in the *same process* on the same context are subject
to the same two conditions; both hold with the defaults.

## Firewalls

**Symptom:** queries are sent (visible in a packet capture on the sender) but
no responses arrive, or the service is visible to some hosts only.

mDNS requires:

- inbound and outbound UDP on port 5353,
- the multicast group `224.0.0.251` (IPv4) — and `ff02::fb` for IPv6
  deployments,
- IGMP (IPv4) / MLD (IPv6) group membership messages not being dropped.

Platform notes:

- **Linux (firewalld):** `firewall-cmd --add-service=mdns --permanent`.
  With raw nftables/iptables, accept `udp dport 5353` and `igmp`.
- **Windows:** the inbound rules "mDNS (UDP-In)" exist per profile
  (Domain/Private/Public) and are disabled on Public networks by default — a
  machine classified on a Public network does not answer or receive mDNS.
- **macOS:** the application firewall prompts per application; denying the
  prompt silently drops inbound 5353.

A reliable first check is `tcpdump -i <if> udp port 5353` (or Wireshark with
filter `mdns`) on both ends: it distinguishes "never sent", "sent but not
received", and "received but not answered".

## VPNs and virtual interfaces

**Symptom:** discovery returns nothing, returns only stale results, or the
server announces on the wrong network.

- **Default-route capture.** Many VPN clients install a default route and/or
  block multicast on the physical interface. mDNS is link-local by design
  (the RFC 6762 §11 TTL-255 convention); most VPN tunnels do not forward
  multicast at all, so traffic sent into the tunnel disappears silently.
- **Interface selection.** When the host has multiple candidate interfaces
  (Ethernet, Wi-Fi, `tun0`, container bridges, libvirt/VirtualBox host-only
  adapters), bind explicitly: set
  `socket_options::interface_address` to the IPv4 address of the interface
  to use. Unset, the OS routing table chooses the egress interface for
  multicast — frequently the VPN or a virtual bridge.
- **Multiple real interfaces.** To operate on all physical interfaces at
  once, use `nic_group` / `dynamic_nic_group` with an `interface_filter`
  excluding virtual adapters, rather than one peer on an unspecified
  interface. See [nic-group.md](nic-group.md).
- **Containers.** A container on a bridge network is a different link;
  mDNS does not cross it. Use host networking (`--network host`) or an mDNS
  reflector if discovery must span the boundary.

## IGMP snooping

**Symptom:** discovery works for a while after a peer starts, then silently
stops; or works between some pairs of hosts on the same switch but not
others; or breaks only across Wi-Fi.

Managed switches with IGMP snooping forward multicast only to ports that have
recently sent an IGMP membership report. Failure modes:

- **No IGMP querier on the segment.** Snooping tables age out (typically
  2–5 minutes) and group traffic stops being forwarded. Enable an IGMP
  querier on the switch or router, or disable snooping for the mDNS VLAN.
- **224.0.0.251 special-casing.** Some switches exempt the 224.0.0.0/24
  link-local block from snooping (correct per RFC 4541); others do not.
  If hosts disagree about visibility, check the switch's snooping
  configuration for link-local multicast.
- **Wi-Fi multicast-to-unicast conversion and power-save buffering** on
  access points drop or delay multicast frames; many enterprise APs have an
  explicit "multicast enhancement"/"mDNS snooping" toggle that interferes.

The kernel re-sends IGMP reports when a socket joins the group, so restarting
the affected peer temporarily "fixing" discovery is a strong indicator of a
snooping/querier problem.

## Multicast loopback

**Symptom:** a process sees its own announcements (often surprising in an
`observer`), or — after disabling loopback — same-host peers stop seeing
each other.

`socket_options::multicast_loopback` (`loopback_mode`, default
`loopback_mode::enabled`) controls `IP_MULTICAST_LOOP`. Enabled is the
correct setting for almost all deployments: the service server filters the
loopback of its own probes by record-set identity, the consumers deduplicate
by record identity, and same-host discovery depends on it (see above).
Disable it only when no other process on the host consumes mDNS and you want
to avoid the local delivery overhead.

An `observer` performs no filtering at all by design, so with loopback
enabled it reports the host's own traffic; this is correct behavior, not a
defect.

## Receive TTL on transports that cannot supply it

**Symptom:** with `mdns_options::unknown_ttl_policy =
ttl_unknown_policy::reject`, a peer receives nothing.

RFC 6762 §11 receive-side enforcement compares the received packet's IP TTL
against `mdns_options::receive_ttl_minimum`. The TTL is carried in
`recv_metadata::ttl` (`std::optional<uint8_t>`), extracted natively by
`default_socket` and `asio_socket` on Linux, macOS, and Windows. It is
`std::nullopt` when the transport cannot supply it: custom policy sockets
that do not populate it, the inproc bus, and Windows systems where the
`WSARecvMsg` extension is unavailable.

`ttl_unknown_policy` decides what happens to those packets:

- `accept` (default) — packets without a TTL are processed normally.
- `reject` — packets without a TTL are silently discarded. On a transport
  that never supplies the TTL this discards *everything*: the peer appears
  deaf with no error reported. Use `reject` only where TTL extraction is
  known to work.

See [api/recv_metadata.md](api/recv_metadata.md) for the platform matrix.

## Where errors surface

mdnspp reports errors through four channels; knowing which one fires saves
time when a peer appears silent.

1. **Construction.** Socket creation/bind failures and invalid options
   (`std::errc::invalid_argument` — e.g. non-positive `silence_timeout`,
   `probe_count == 0`, `response_delay_min > response_delay_max`, empty
   service names) throw `std::system_error` from the throwing constructors,
   or set the trailing `std::error_code &` on the non-throwing overloads.
2. **Completion handlers.** Each `async_*` initiating function completes
   exactly once with a `std::error_code`: `std::error_code{}` on natural
   completion, `std::errc::operation_canceled` on `stop()`/destruction,
   `std::errc::operation_in_progress` / `std::errc::invalid_argument` on
   one-shot misuse, `mdns_error::invalid_name` for names failing RFC 1035
   §5.1 validation, and `mdns_error::probe_conflict` for a server whose
   probing fails permanently (delivered to `on_ready`; `on_done` still fires
   after teardown).
3. **`on_error` options fields.** Fire-and-forget send failures and fatal
   receive errors do not fail the operation; they are reported through the
   `on_error` field of `service_options`, `monitor_options`, `query_options`,
   and `observer_options` (`void(std::error_code, std::string_view)`, the
   string naming the failure site, e.g. `"probe send"`, `"receive"`).
   **Without a handler these errors are silently ignored** — set `on_error`
   in any deployment where you need to observe send/receive failures.
4. **Error codes.** Library-specific conditions use the `mdns_error` enum
   (`<mdnspp/mdns_error.h>`, category `"mdns"`); portable conditions use
   `std::errc`. Compare with `ec == mdnspp::mdns_error::probe_conflict`
   etc.; `make_error_code` is provided.

See [api/errors.md](api/errors.md) for the full error reference.

## See Also

- [Socket Options](socket-options.md) — interface selection, multicast TTL, loopback
- [NIC Group](nic-group.md) — multi-interface operation
- [api/errors.md](api/errors.md) — `mdns_error` and error-code conventions
- [rfc/receive-ttl.md](rfc/receive-ttl.md) — RFC 6762 §11 receive-side TTL verification
