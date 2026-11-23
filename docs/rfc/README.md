# RFC Compliance

mdnspp targets conformance with [RFC 6762](https://datatracker.ietf.org/doc/html/rfc6762) (Multicast DNS) and [RFC 6763](https://datatracker.ietf.org/doc/html/rfc6763)
(DNS-Based Service Discovery). The table below shows which requirements
are implemented and which remain pending.

**Legend:** `[x]` implemented -- `[~]` partially implemented -- `[ ]` not yet implemented

## RFC 6762 -- Multicast DNS

| RFC Section | Feature | Status | Documentation |
|-------------|---------|--------|---------------|
| 5.2 | Initial query delay (20–120 ms random) | `[x]` | [traffic-reduction.md](traffic-reduction.md) |
| 5.2 | Continuous query backoff (1 s → 60 min) | `[x]` | [query-backoff.md](query-backoff.md) |
| 5.2 | TTL refresh queries (80/85/90/95%) | `[x]` | [query-backoff.md](query-backoff.md) |
| 5.4 | QU/QM response routing (incl. quarter-TTL multicast rule) | `[x]` | [quqm-routing.md](quqm-routing.md) |
| 5.5 | Direct unicast queries: "responders SHOULD check that the source address in the query packet matches the local subnet for that link (or, in the case of IPv6, the source address has an on-link prefix) and silently ignore the packet if not." | `[x]` | A query sent to a unicast address from a source outside the on-link prefixes of the receiving interface is dropped. A query whose destination is unknown is always kept, so a legacy querier (6.7) is never left without its reply. In-process transports are exempt |
| 6/7.2 | TC bit and multi-packet known-answer (both sides) | `[x]` | [tc-handling.md](tc-handling.md) |
| 6 | Random response delay (20–120 ms) | `[x]` | [traffic-reduction.md](traffic-reduction.md) |
| 6 | Parameterized response delay (20–120 ms) | `[x]` | [mdns_options](../api/mdns_options.md): response_delay_min/max |
| 6 | Class and type matching of questions (qtype and qclass ANY, QU bit masked) | `[x]` | Questions of a class other than IN or ANY are not answered |
| 6 | Unicast responses: "A Multicast DNS querier MUST only accept unicast responses if they answer a recently sent query (e.g., sent within the last two seconds) that explicitly requested unicast responses.  A Multicast DNS querier MUST silently ignore all other unicast responses." | `[x]` | Every peer type accepts a response sent to a unicast address only if its answer section answers a QU question the peer sent within [qu_response_window](../api/options/qu_response_window_in_mdns_options.md) (2 s by default); queriers, service discovery and probes record their QU questions. In-process transports are held to it. Where the destination is unknown the rule is skipped and only the on-link test (11) applies. No mdnspp peer is a legacy querier: each binds the configured port. [quqm-routing.md](quqm-routing.md) |
| 6 | Source port of received responses: "Multicast DNS implementations MUST silently ignore any Multicast DNS responses they receive where the source UDP port is not 5353." | `[x]` | Every peer type drops a response from a port other than the configured multicast port; queries from any port are kept (6.7). In-process transports are exempt: [inproc-bus.md](../inproc-bus.md) |
| 6.1 | Negative responses (NSEC, per-name owner and type bitmap) | `[x]` | [negative-responses.md](negative-responses.md) |
| 6.1 | Querier-side NSEC consumption | `[ ]` | Received NSEC records are not used to suppress retries |
| 6.7 | Legacy unicast responses (ID/question echo, no cache-flush, TTL cap) | `[x]` | [legacy-unicast.md](legacy-unicast.md) |
| 7.1 | Known-answer suppression (rdata-matched) | `[x]` | [known-answer-suppression.md](known-answer-suppression.md) |
| 7.3 | Duplicate question suppression (empty-KA rule) | `[x]` | [traffic-reduction.md](traffic-reduction.md), [duplicate-suppression.md](duplicate-suppression.md) |
| 7.4 | Duplicate answer suppression | `[x]` | [duplicate-suppression.md](duplicate-suppression.md) |
| 8.1 | Probing (3 probes at 250 ms; instance name and hostname) | `[x]` | [probing.md](probing.md) |
| 8.1 | Parameterized probe count and intervals | `[x]` | [service_options](../api/service_options.md): probe_count, probe_interval, probe_initial_delay_max |
| 8.1 | Probe rate limiting (15 conflicts/10 s → 5 s delay) | `[x]` | [probing.md](probing.md) |
| 8.2.1 | Simultaneous probe tiebreaking | `[x]` | [probing.md](probing.md): uncompressed record-set comparison, identical sets are not a conflict |
| 8.3 | Announcing (configurable burst) | `[x]` | [probing.md](probing.md) |
| 9 | Post-probe conflict detection (re-probe/rename while live) | `[x]` | [probing.md](probing.md) |
| 10 | Record TTL defaults (4500 s; 120 s for host-name-containing records) | `[x]` | [service_options](../api/service_options.md) |
| 10.1 | Goodbye packets (TTL=0) | `[x]` | [goodbye.md](goodbye.md) |
| 10.2 | Cache-flush bit (young-record exemption) | `[x]` | [cache-flush.md](cache-flush.md) |
| 10.2 | Cache-flush scope: name, rrtype and rrclass | `[x]` | [record-cache.md](../record-cache.md): records of another class are not flushed |
| 10.5 | Passive Observation Of Failures (POOF) | `[ ]` | Not implemented |
| 11 | Multicast TTL 255 | `[x]` | [socket-options.md](../socket-options.md) |
| 11 | Receive-side TTL 255 enforcement | `[x]` | [receive-ttl.md](receive-ttl.md) -- [recv_metadata](../api/recv_metadata.md) |
| 11 | Local-link responses: "A host sending Multicast DNS queries to a link-local destination address (including the 224.0.0.251 and FF02::FB link-local multicast addresses) MUST only accept responses to that query that originate from the local link, and silently discard any other response packets." | `[x]` | Every peer type deems a response sent to a multicast address on-link. A response sent to a unicast address passes only if its source lies in an on-link prefix of the receiving interface or is one of this host's own addresses. Where the destination is unknown (the platform does not report it, or the control data was truncated) the same source test applies to every response: an on-link unicast response is accepted, and a multicast response from outside the local prefixes is dropped. In-process transports are exempt: [inproc-bus.md](../inproc-bus.md). See [recv_metadata](../api/recv_metadata.md) |
| 18.3 | OPCODE: "Multicast DNS messages received with an OPCODE other than zero MUST be silently ignored." | `[x]` | Every peer type drops such packets, and packets shorter than a DNS header |
| 18.11 | RCODE: "Multicast DNS messages received with non-zero Response Codes MUST be silently ignored." | `[x]` | Every peer type drops such packets |

## RFC 6763 -- DNS-Based Service Discovery

| RFC Section | Feature | Status | Documentation |
|-------------|---------|--------|---------------|
| 6 | TXT record key-value pairs | `[x]` | [txt-records.md](txt-records.md) |
| 7.1 | Subtype queries | `[x]` | [dns-sd.md](dns-sd.md) |
| 9 | Service type enumeration | `[x]` | [dns-sd.md](dns-sd.md) |
| — | Configurable per-record TTL | `[x]` | [service_options](../api/service_options.md) per-type TTLs (ptr_ttl, srv_ttl, txt_ttl, a_ttl, aaaa_ttl) |

## See Also

- [Continuous Querying and Backoff](query-backoff.md)
- [TC Bit and Multi-Packet Known-Answer](tc-handling.md)
- [Duplicate Answer Suppression](duplicate-suppression.md)
- [Cache-Flush Bit](cache-flush.md)
- [Probing and Conflict Resolution](probing.md)
- [Goodbye Packets](goodbye.md)
- [Known-Answer Suppression](known-answer-suppression.md)
- [Traffic Reduction](traffic-reduction.md)
- [DNS-SD: Enumeration and Subtypes](dns-sd.md)
