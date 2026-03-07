#ifndef HPP_GUARD_MDNSPP_SERVICE_INFO_H
#define HPP_GUARD_MDNSPP_SERVICE_INFO_H

#include "mdnspp/records.h"

#include <string>
#include <vector>
#include <cstdint>
#include <optional>

namespace mdnspp {

// service_info — public vocabulary type describing an mDNS service to announce.
//
// Passed to service_server<P> to specify what the server will respond to
// and what data it will include in DNS responses (RFC 6762 / RFC 6763).
//
// Field naming follows RFC 6763 terminology:
//   service_name  — fully-qualified service instance name, e.g. "MyApp._http._tcp.local."
//   service_type  — service type (PTR owner), e.g. "_http._tcp.local."
//   hostname      — target hostname for SRV/A/AAAA records, e.g. "myhost.local."
//   port          — TCP/UDP port the service listens on
//   priority      — SRV priority (lower = more preferred)
//   weight        — SRV weight (for load balancing among equal-priority targets)
//   address_ipv4  — optional IPv4 address string, e.g. "192.168.1.10"
//   address_ipv6  — optional IPv6 address string, e.g. "fe80::1"
//   txt_records   — RFC 6763 TXT key/value pairs (key-only entries have no value)
struct service_info
{
    std::string service_name; // e.g. "MyApp._http._tcp.local."
    std::string service_type; // e.g. "_http._tcp.local."
    std::string hostname;     // e.g. "myhost.local."
    uint16_t port{0};
    uint16_t priority{0};
    uint16_t weight{0};
    std::optional<std::string> address_ipv4; // e.g. "192.168.1.10"
    std::optional<std::string> address_ipv6; // e.g. "fe80::1"
    std::vector<service_txt> txt_records;    // RFC 6763 key/value or key-only entries
    std::vector<std::string> subtypes;      // e.g. {"_printer"} for subtype enumeration
};

}

#endif
