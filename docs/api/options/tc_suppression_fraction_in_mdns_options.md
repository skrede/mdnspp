# tc_suppression_fraction in mdns_options

| Attribute | Value |
|-----------|-------|
| **Type** | `double` |
| **Default** | `0.5` |
| **One-liner** | Fraction of wire TTL used as the known-answer suppression threshold on the TC path |

## What

`tc_suppression_fraction` mirrors `ka_suppression_fraction` but applies specifically to the TC (truncated) accumulation code path (RFC 6762 §7.1). When the TC accumulator collects known answers from multiple continuation packets, it uses this threshold to decide whether each known answer is fresh enough to suppress re-announcement.

Having a separate field allows TC-path suppression to be tuned independently of the standard query path. In most deployments both fields hold the same value of `0.5`, but they can diverge when TC queries carry older known answers than standard queries (e.g., in large-scale setups where TC assembly adds latency that ages the records).

## Why

The default of `0.5` matches `ka_suppression_fraction` and implements the RFC §7.1 threshold. Keeping both fields equal is correct for the vast majority of deployments.

Reasons to adjust `tc_suppression_fraction` independently:

- **Lower** — if TC queries tend to carry slightly aged known answers due to the assembly delay (`tc_wait_min`/`tc_wait_max`), lowering this fraction slightly (e.g., to `0.45`) avoids incorrectly rejecting valid suppressions caused by the wait window aging the known-answer TTLs.
- **Higher** — if TC-path suppression correctness is more critical than traffic reduction in a specific deployment, requiring fresher known answers on the TC path ensures re-announcements cover any gaps.

## Danger

The same trade-offs as `ka_suppression_fraction` apply: lowering accepts stale known answers (risking cache gaps), raising causes more re-announcements (increasing traffic). The difference is that these risks are confined to the TC accumulation code path — queries without the TC bit set are unaffected.

Mismatching `tc_suppression_fraction` and `ka_suppression_fraction` significantly (e.g., `0.1` vs `0.9`) creates inconsistent suppression behaviour: the same record may be suppressed when seen in a standard query but re-announced when the same record arrives in a TC query, or vice versa. This inconsistency is generally undesirable.
