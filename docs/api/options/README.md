# Options Deep-Dive Pages

This directory contains one deep-dive page per field across all three options structs:

- [`mdns_options`](../mdns_options.md) — protocol tunables for querying, TTL refresh, and TC accumulation
- [`service_options`](../service_options.md) — service announcement, probing, and TTL configuration
- [`cache_options`](../cache_options.md) — cache eviction and goodbye grace behaviour

Each page covers **What** the field controls, **Why** you would change it from the default, and **Danger** (risks and failure modes).

---

## mdns_options fields

| Page | One-liner |
|------|-----------|
| [initial_interval](initial_interval_in_mdns_options.md) | Starting interval for the exponential query backoff (RFC 6762 §5.2) |
| [max_interval](max_interval_in_mdns_options.md) | Upper bound on the exponential backoff interval |
| [backoff_multiplier](backoff_multiplier_in_mdns_options.md) | Multiplicative factor applied on each backoff step |
| [ttl_refresh_thresholds](ttl_refresh_thresholds_in_mdns_options.md) | Fractional TTL thresholds at which refresh queries are issued |
| [refresh_jitter_pct](refresh_jitter_pct_in_mdns_options.md) | Maximum jitter applied to refresh query fire points |
| [tc_wait_min](tc_wait_min_in_mdns_options.md) | Minimum wait for accumulating TC continuation packets |
| [tc_wait_max](tc_wait_max_in_mdns_options.md) | Maximum wait for accumulating TC continuation packets |
| [max_known_answers](max_known_answers_in_mdns_options.md) | Maximum known-answer records in outgoing queries |
| [record_ttl](record_ttl_in_mdns_options.md) | Default TTL for outgoing DNS resource records |
| [response_delay_min](response_delay_min_in_mdns_options.md) | Minimum random delay before sending a multicast response |
| [response_delay_max](response_delay_max_in_mdns_options.md) | Maximum random delay before sending a multicast response |
| [legacy_unicast_ttl](legacy_unicast_ttl_in_mdns_options.md) | TTL cap for records sent in legacy unicast responses |
| [ka_suppression_fraction](ka_suppression_fraction_in_mdns_options.md) | Known-answer suppression threshold fraction for standard queries |
| [tc_suppression_fraction](tc_suppression_fraction_in_mdns_options.md) | Known-answer suppression threshold fraction on the TC path |
| [max_query_payload](max_query_payload_in_mdns_options.md) | Maximum UDP payload before TC packet splitting |
| [tc_continuation_delay](tc_continuation_delay_in_mdns_options.md) | Delay between successive TC continuation packets |
| [receive_ttl_minimum](receive_ttl_minimum_in_mdns_options.md) | Minimum IP TTL for received mDNS packets |

---

## service_options fields

| Page | One-liner |
|------|-----------|
| [on_conflict](on_conflict_in_service_options.md) | Invoked when a name conflict is detected; returns true to accept the proposed new name |
| [on_query](on_query_in_service_options.md) | Fired each time the service receives an incoming query matching its records |
| [on_tc_continuation](on_tc_continuation_in_service_options.md) | Fired when a TC continuation batch is processed |
| [announce_count](announce_count_in_service_options.md) | Number of unsolicited announcement packets sent after probing completes |
| [announce_interval](announce_interval_in_service_options.md) | Delay between successive announcement packets |
| [send_goodbye](send_goodbye_in_service_options.md) | Whether to send a goodbye packet (TTL=0) on graceful shutdown |
| [suppress_known_answers](suppress_known_answers_in_service_options.md) | Whether the service honours known-answer suppression |
| [respond_to_meta_queries](respond_to_meta_queries_in_service_options.md) | Whether to respond to DNS-SD meta-queries |
| [announce_subtypes](announce_subtypes_in_service_options.md) | Whether to announce sub-type PTR records alongside the primary PTR |
| [probe_count](probe_count_in_service_options.md) | Number of probe packets sent before announcing begins |
| [probe_interval](probe_interval_in_service_options.md) | Interval between successive probe packets |
| [probe_initial_delay_max](probe_initial_delay_max_in_service_options.md) | Upper bound on the random initial delay before the first probe |
| [respond_to_legacy_unicast](respond_to_legacy_unicast_in_service_options.md) | Whether to respond to legacy unicast queries (source port ≠ 5353) |
| [ptr_ttl](ptr_ttl_in_service_options.md) | TTL for PTR records in outgoing responses |
| [srv_ttl](srv_ttl_in_service_options.md) | TTL for SRV records in outgoing responses |
| [txt_ttl](txt_ttl_in_service_options.md) | TTL for TXT records in outgoing responses |
| [a_ttl](a_ttl_in_service_options.md) | TTL for A (IPv4 address) records in outgoing responses |
| [aaaa_ttl](aaaa_ttl_in_service_options.md) | TTL for AAAA (IPv6 address) records in outgoing responses |
| [record_ttl](record_ttl_in_service_options.md) | Fallback TTL for NSEC and meta-query PTR records |
| [probe_authority_ttl](probe_authority_ttl_in_service_options.md) | TTL for SRV records in probe authority sections (tiebreaking) |
| [probe_defer_delay](probe_defer_delay_in_service_options.md) | Delay before re-probing after losing a simultaneous-probe tiebreak |

---

## cache_options fields

| Page | One-liner |
|------|-----------|
| [on_expired](on_expired_in_cache_options.md) | Fired when cache entries expire naturally |
| [on_cache_flush](on_cache_flush_in_cache_options.md) | Fired when a Cache Flush record evicts conflicting cached entries |
| [goodbye_grace](goodbye_grace_in_cache_options.md) | Grace period for goodbye records (TTL=0) before cache eviction |
