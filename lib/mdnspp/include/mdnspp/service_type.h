#ifndef HPP_GUARD_MDNSPP_SERVICE_TYPE_H
#define HPP_GUARD_MDNSPP_SERVICE_TYPE_H

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
// Expects at least three dot-separated labels: type, protocol, domain.
inline service_type_info parse_service_type(std::string_view name)
{
    // Strip trailing dot if present
    if(!name.empty() && name.back() == '.')
        name.remove_suffix(1);

    service_type_info info;
    info.service_type = std::string(name);

    // Split on dots
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

}

#endif
