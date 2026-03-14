# probe_authority_ttl in service_options

| | |
|---|---|
| **Type** | `std::chrono::seconds` |
| **Default** | `120` |
| **RFC** | RFC 6762 §8.2 |
| **One-liner** | TTL for SRV records placed in the authority section of probe queries for simultaneous-probe tiebreaking. |

## What

During the probe phase, when another host's probe for the same name is detected, RFC 6762 §8.2 specifies a tiebreaking algorithm: each host includes its own records in the authority section of probe queries. The host with the lexicographically greater rdata wins.

`probe_authority_ttl` is the TTL value placed on the SRV record in this authority section. RFC 6762 §8.2 specifies 120 seconds for probe authority records. The authority TTL is not used for caching purposes by recipients — it is only present because a valid DNS resource record requires a non-zero TTL.

## Why

In practice there is almost no reason to change `probe_authority_ttl`. The value is effectively ignored by recipients in the tiebreaking context. The field exists for completeness and potential future RFC revisions.

Change it only if:

- A specific interoperability scenario with an unusual mDNS implementation requires a different authority TTL.
- Intentional RFC deviation is required for testing purposes.

## Danger

- **Changing this value has no interoperability impact** under RFC 6762 §8.2 as currently specified. Recipients of probe queries do not cache authority section records.
- Setting this to zero produces a malformed DNS record (TTL=0 in a non-goodbye authority record), which may cause parsing failures in strict implementations.
- This field is unlikely to ever need manual configuration in production deployments.
