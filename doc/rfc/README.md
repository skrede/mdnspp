# RFC Compliance

mdnspp targets conformance with RFC 6762 (Multicast DNS) and RFC 6763
(DNS-Based Service Discovery). The tables below show which requirements
are implemented and which remain pending.

**Legend:** `[x]` implemented -- `[ ]` not yet implemented

## RFC 6762 -- Multicast DNS

| Status | Section | Feature | Notes |
|--------|---------|---------|-------|
| `[x]` | 5.2 | Initial query delay (20--120 ms random) | [traffic-reduction.md](traffic-reduction.md) |
| `[ ]` | 5.2 | Continuous query backoff | Exponential re-query intervals not implemented |
| `[x]` | 5.4 | QU/QM response routing | QU bit selects unicast vs multicast response |
| `[ ]` | 5.4/7.2 | TC bit and multi-packet known-answer | Not implemented |
| `[x]` | 6 | Random response delay (20--120 ms) | [traffic-reduction.md](traffic-reduction.md) |
| `[x]` | 6.1 | Negative responses (NSEC) | NSEC records for unmatched query types |
| `[ ]` | 6.7 | Legacy unicast responses | Source port != 5353 not handled |
| `[x]` | 7.1 | Known-answer suppression | [known-answer-suppression.md](known-answer-suppression.md) |
| `[x]` | 7.3 | Duplicate question suppression | [traffic-reduction.md](traffic-reduction.md) |
| `[ ]` | 7.4 | Duplicate answer suppression | Not implemented |
| `[x]` | 8.1 | Probing (3 probes at 250 ms) | [probing.md](probing.md) |
| `[ ]` | 8.1 | Simultaneous probe tiebreaking | Simplified: any match = conflict |
| `[x]` | 8.3 | Announcing (configurable burst) | [probing.md](probing.md) |
| `[x]` | 10.1 | Goodbye packets (TTL=0) | [goodbye.md](goodbye.md) |
| `[ ]` | 10/14 | Client-side record cache with TTL expiry | Not implemented |
| `[x]` | 11 | Multicast TTL 255 | Default via `socket_options` |

## RFC 6763 -- DNS-Based Service Discovery

| Status | Section | Feature | Notes |
|--------|---------|---------|-------|
| `[x]` | 6 | TXT record key-value pairs | Encoded per RFC 6763 section 6 |
| `[x]` | 7.1 | Subtype queries | [dns-sd.md](dns-sd.md) |
| `[x]` | 9 | Service type enumeration | [dns-sd.md](dns-sd.md) |
| `[ ]` | -- | Configurable per-record TTL | All records use fixed 4500 s TTL |

## See Also

- [Probing and Conflict Resolution](probing.md)
- [Goodbye Packets](goodbye.md)
- [Known-Answer Suppression](known-answer-suppression.md)
- [Traffic Reduction](traffic-reduction.md)
- [DNS-SD: Enumeration and Subtypes](dns-sd.md)
