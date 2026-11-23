# qu_response_window in mdns_options

| Attribute | Value |
|-----------|-------|
| **Type** | `std::chrono::milliseconds` |
| **Default** | `std::chrono::seconds(2)` |
| **Validation** | Must be greater than zero; otherwise the constructor reports `std::errc::invalid_argument` |
| **One-liner** | How long after sending a QU question a peer accepts unicast responses that answer it |

## What

A response addressed to one of this host's unicast addresses is accepted only if one of the records in its answer section answers a question this peer sent with the unicast-response (QU) bit within the last `qu_response_window`. A record answers a question when its name matches the question name (ignoring ASCII case), its type matches the question type unless the question asked for ANY or the record is a CNAME, and its class matches the question class unless the question asked for class ANY. Records in the authority and additional sections do not count. Every other unicast response is silently ignored.

The peers that send QU questions record them as they send:

- a querier started with `response_mode::unicast`;
- a service discovery started with `response_mode::unicast`;
- a service server while it probes: each probe asks two QU questions of type ANY (the instance name and the host name), so a defender's unicast reply to a probe is accepted and conflict handling runs.

An observer and a service monitor send no QU questions, so they ignore every unicast response. Responses sent to a multicast address are not affected.

Each peer keeps at most 64 recent QU questions; entries older than the window are dropped, and the oldest entry makes room once the limit is reached.

The rule also applies to the in-process transport, which is exempt only from the source-port and on-link rules.

## Why

RFC 6762 §6:

> A Multicast DNS querier MUST only accept unicast responses if they answer a recently sent query (e.g., sent within the last two seconds) that explicitly requested unicast responses.  A Multicast DNS querier MUST silently ignore all other unicast responses.

The default is the two seconds of the RFC's example. Raise the window on a link where replies to QU questions are slow to arrive, for example behind a congested access point.

The RFC's rule applies outside legacy unicast. No mdnspp peer is a legacy querier: every peer binds the configured multicast port, so the rule applies to every unicast response a peer receives.

## Unknown destination

Where the platform does not report the destination address of a datagram, or the control data that carries it was truncated, a peer cannot tell a unicast response from a multicast one. Such a response skips this rule and keeps only the on-link source test of RFC 6762 §11; counting it as unicast would drop every multicast response on that platform. On such a platform an on-link unicast response that answers no recent QU question is therefore accepted. See [recv_metadata](../recv_metadata.md).

## Danger

1. **Too long a window** widens the time in which a host on the link can unicast unsolicited answers to a name this peer asked about, and have them cached.
2. **Too short a window** drops legitimate unicast replies that arrive late. A querier then sees fewer answers, and a probing server may miss a defender's unicast reply and claim a name that is already taken.
