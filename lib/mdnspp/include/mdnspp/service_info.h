#ifndef HPP_GUARD_MDNSPP_SERVICE_INFO_H
#define HPP_GUARD_MDNSPP_SERVICE_INFO_H

#include "mdnspp/records.h"
#include "mdnspp/mdns_error.h"
#include "mdnspp/service_type.h"

#include "mdnspp/detail/compat.h"
#include "mdnspp/detail/service_names.h"

#include <string>
#include <vector>
#include <cstdint>
#include <utility>
#include <optional>
#include <string_view>

namespace mdnspp {

// service_make_options — optional parameters for service_info::make().
//
//   hostname            — target hostname; a single label or a name ending in
//                         ".local" (trailing dot optional); the ".local."
//                         suffix is appended when missing. Unset: the OS
//                         hostname (::gethostname), stripped of any domain
//                         part, with ".local." appended.
//   priority, weight    — SRV priority and weight (RFC 2782 semantics).
//   address_ipv4/ipv6   — explicit addresses; each field left unset is
//                         auto-detected at async_start (see
//                         service_info::auto_address).
//   advertise_addresses — false: no A/AAAA records are announced; both
//                         address fields are left unset and auto-detection is
//                         disabled.
//   txt_records         — RFC 6763 TXT key/value pairs.
//   subtypes            — DNS-SD subtype labels (RFC 6763 §7.1).
struct service_make_options
{
    std::optional<std::string> hostname{};
    uint16_t priority{0};
    uint16_t weight{0};
    std::optional<std::string> address_ipv4{};
    std::optional<std::string> address_ipv6{};
    bool advertise_addresses{true};
    std::vector<service_txt> txt_records{};
    std::vector<std::string> subtypes{};
};

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
//   subtypes      — DNS-SD subtype labels, e.g. {"_printer"}
//   auto_address  — set by make(): the server fills the unset address fields
//                   at async_start (and on update_service_info) with addresses
//                   of the announcing interface (RFC 6762 §6.2). Aggregate
//                   initialization leaves it false, so an aggregate-built
//                   service_info keeps the omit-when-unset semantics.
struct service_info
{
    dns_name service_name; // e.g. "MyApp._http._tcp.local."
    dns_name service_type; // e.g. "_http._tcp.local."
    dns_name hostname;     // e.g. "myhost.local."
    uint16_t port{0};
    uint16_t priority{0};
    uint16_t weight{0};
    std::optional<std::string> address_ipv4; // e.g. "192.168.1.10"
    std::optional<std::string> address_ipv6; // e.g. "fe80::1"
    std::vector<service_txt> txt_records;    // RFC 6763 key/value or key-only entries
    std::vector<std::string> subtypes;      // e.g. {"_printer"} for subtype enumeration
    bool auto_address{false};               // set by make(); see the struct comment

    // Builds a validated service_info from an unescaped instance label and a
    // service type.
    //
    //   instance     — unescaped UTF-8 instance label; '.' and '\' are escaped
    //                  per RFC 1035 §5.1 ("Dr. Smith" stays one label).
    //   service_type — "_http._tcp" or "_http._tcp.local."; ".local." is
    //                  appended when the input carries no domain (trailing dot
    //                  optional in all forms).
    //   port         — the port the service listens on; 0 is rejected with
    //                  mdns_error::invalid_argument.
    //
    // Errors: mdns_error::invalid_name for a structurally invalid service
    // type (parse_service_type_checked), an instance label or hostname that
    // fails dns_name::parse() (empty label, label over 63 octets, name over
    // 255 octets), or an unusable OS hostname; mdns_error::invalid_argument
    // for port == 0.
    [[nodiscard]] static expected<service_info, mdns_error>
    make(std::string_view instance, std::string_view service_type,
         uint16_t port, service_make_options opts = {});
};

namespace detail {

inline void apply_make_options(service_info &info, service_make_options &&opts)
{
    info.priority = opts.priority;
    info.weight = opts.weight;
    info.txt_records = std::move(opts.txt_records);
    info.subtypes = std::move(opts.subtypes);
    if(!opts.advertise_addresses)
        return;
    info.address_ipv4 = std::move(opts.address_ipv4);
    info.address_ipv6 = std::move(opts.address_ipv6);
    // Auto-detection fills only the fields the caller left unset.
    info.auto_address = !(info.address_ipv4.has_value() && info.address_ipv6.has_value());
}

}

inline expected<service_info, mdns_error>
service_info::make(std::string_view instance, std::string_view service_type,
                   uint16_t port, service_make_options opts)
{
    if(port == 0)
        return detail::unexpected(mdns_error::invalid_argument);

    auto names = detail::parse_service_names(instance, service_type, std::move(opts.hostname));
    if(!names.has_value())
        return detail::unexpected(names.error());

    service_info info;
    info.service_name = std::move(names->instance);
    info.service_type = std::move(names->type);
    info.hostname = std::move(names->host);
    info.port = port;
    detail::apply_make_options(info, std::move(opts));
    return info;
}

}

#endif
