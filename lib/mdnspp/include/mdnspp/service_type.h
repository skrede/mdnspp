#ifndef HPP_GUARD_MDNSPP_SERVICE_TYPE_H
#define HPP_GUARD_MDNSPP_SERVICE_TYPE_H

#include "mdnspp/mdns_error.h"

#include "mdnspp/detail/compat.h"

#include <string>
#include <cstddef>
#include <utility>
#include <string_view>

namespace mdnspp {

struct service_type_info
{
    std::string service_type; // "_http._tcp.local", without a trailing dot
    std::string type_name;    // "_http"
    std::string protocol;     // "_tcp"
    std::string domain;       // "local"
};

namespace detail {

// Without a dot the whole name is the label and the remainder is empty.
inline std::pair<std::string_view, std::string_view> split_first_label(std::string_view name)
{
    const std::size_t dot = name.find('.');
    if(dot == std::string_view::npos)
        return {name, {}};
    return {name.substr(0, dot), name.substr(dot + 1)};
}

}

// Parses a DNS-SD service type name (e.g. "_http._tcp.local") into components.
// Lenient: missing labels yield empty fields. Use parse_service_type_checked
// when the input must be a structurally complete DNS-SD service type.
inline service_type_info parse_service_type(std::string_view name)
{
    if(name.ends_with('.'))
        name.remove_suffix(1);

    service_type_info info;
    info.service_type = std::string(name);
    if(name.find('.') == std::string_view::npos)
        return info;

    const auto [type_name, rest] = detail::split_first_label(name);
    const auto [protocol, domain] = detail::split_first_label(rest);
    info.type_name = std::string(type_name);
    info.protocol  = std::string(protocol);
    info.domain    = std::string(domain);
    return info;
}

// Strict variant of parse_service_type. Returns mdns_error::invalid_name
// unless the name contains the three labels required by RFC 6763 (type,
// protocol, domain) and all of them are non-empty.
inline expected<service_type_info, mdns_error> parse_service_type_checked(std::string_view name)
{
    auto info = parse_service_type(name);
    if(info.type_name.empty() || info.protocol.empty() || info.domain.empty())
        return detail::unexpected(mdns_error::invalid_name);
    return info;
}

}

#endif
