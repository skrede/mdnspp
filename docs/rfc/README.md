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
| 5.4 | QU/QM response routing | `[x]` | — |
| 5.4/7.2 | TC bit and multi-packet known-answer | `[x]` | [tc-handling.md](tc-handling.md) |
| 6 | Random response delay (20–120 ms) | `[x]` | [traffic-reduction.md](traffic-reduction.md) |
| 6 | Parameterized response delay (20–120 ms) | `[x]` | mdns_options: response_delay_min/max |
| 6.1 | Negative responses (NSEC) | `[x]` | — |
| 6.7 | Legacy unicast responses | `[x]` | service_options::respond_to_legacy_unicast |
| 7.1 | Known-answer suppression | `[x]` | [known-answer-suppression.md](known-answer-suppression.md) |
| 7.3 | Duplicate question suppression | `[x]` | [traffic-reduction.md](traffic-reduction.md) |
| 7.4 | Duplicate answer suppression | `[x]` | [duplicate-suppression.md](duplicate-suppression.md) |
| 8.1 | Probing (3 probes at 250 ms) | `[x]` | [probing.md](probing.md) |
| 8.1 | Parameterized probe count and intervals | `[x]` | service_options: probe_count, probe_interval, probe_initial_delay_max |
| 8.1 | Simultaneous probe tiebreaking | `[x]` | Full §8.2 tiebreak with SRV rdata comparison |
| 8.3 | Announcing (configurable burst) | `[x]` | [probing.md](probing.md) |
| 10.1 | Goodbye packets (TTL=0) | `[x]` | [goodbye.md](goodbye.md) |
| 10.2 | Cache-flush bit | `[x]` | [cache-flush.md](cache-flush.md) |
| 11 | Multicast TTL 255 | `[x]` | [socket-options.md](../socket-options.md) |
| 11 | Receive-side TTL 255 enforcement | `[x]` | [receive_ttl_minimum](../api/options/receive_ttl_minimum_in_mdns_options.md) |

## RFC 6763 -- DNS-Based Service Discovery

| RFC Section | Feature | Status | Documentation |
|-------------|---------|--------|---------------|
| 6 | TXT record key-value pairs | `[x]` | — |
| 7.1 | Subtype queries | `[x]` | [dns-sd.md](dns-sd.md) |
| 9 | Service type enumeration | `[x]` | [dns-sd.md](dns-sd.md) |
| — | Configurable per-record TTL | `[x]` | mdns_options::record_ttl; service_options per-type TTLs (ptr_ttl, srv_ttl, txt_ttl, a_ttl, aaaa_ttl) |

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
