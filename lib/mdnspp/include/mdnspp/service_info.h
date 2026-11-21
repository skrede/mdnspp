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
    std::vector<service_txt> txt_records;
    std::vector<std::string> subtypes;
    bool auto_address{false};

    static expected<service_info, mdns_error>
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
