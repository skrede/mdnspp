#ifndef HPP_GUARD_MDNSPP_SERVICE_TYPE_H
#define HPP_GUARD_MDNSPP_SERVICE_TYPE_H

#include "mdnspp/mdns_error.h"

#include "mdnspp/detail/compat.h"

#include <string>
#include <string_view>

namespace mdnspp {

// Service type information parsed from a DNS-SD PTR name.
struct service_type_info
{
    std::string service_type; // full: "_http._tcp.local" or "_http._tcp.local."
    std::string type_name;    // "_http"
    std::string protocol;     // "_tcp"
    std::string domain;       // "local"
};

// Parses a DNS-SD service type name (e.g. "_http._tcp.local") into components.
// Lenient: missing labels yield empty fields. Use parse_service_type_checked
// when the input must be a structurally complete DNS-SD service type.
[[nodiscard]] inline service_type_info parse_service_type(std::string_view name)
{
    // Strip trailing dot if present
    if(!name.empty() && name.back() == '.')
        name.remove_suffix(1);

    service_type_info info;
    info.service_type = std::string(name);

    size_t first_dot = name.find('.');
    if(first_dot == std::string_view::npos)
        return info;

    info.type_name = std::string(name.substr(0, first_dot));

    size_t second_dot = name.find('.', first_dot + 1);
    if(second_dot == std::string_view::npos)
    {
        info.protocol = std::string(name.substr(first_dot + 1));
        return info;
    }

    info.protocol = std::string(name.substr(first_dot + 1, second_dot - first_dot - 1));
    info.domain = std::string(name.substr(second_dot + 1));

    return info;
}

// Strict variant of parse_service_type. Returns mdns_error::invalid_name
// unless the name contains the three labels required by RFC 6763 (type,
// protocol, domain) and all of them are non-empty.
[[nodiscard]] inline expected<service_type_info, mdns_error>
parse_service_type_checked(std::string_view name)
{
    auto info = parse_service_type(name);
    if(info.type_name.empty() || info.protocol.empty() || info.domain.empty())
        return detail::make_unexpected(mdns_error::invalid_name);
    return info;
}

}

#endif
