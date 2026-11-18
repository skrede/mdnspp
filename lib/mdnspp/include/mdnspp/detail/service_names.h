#ifndef HPP_GUARD_MDNSPP_DETAIL_SERVICE_NAMES_H
#define HPP_GUARD_MDNSPP_DETAIL_SERVICE_NAMES_H

#include "mdnspp/dns_name.h"
#include "mdnspp/mdns_error.h"
#include "mdnspp/service_type.h"

#include "mdnspp/detail/compat.h"
#include "mdnspp/detail/mdns_util.h"

#include <string>
#include <utility>
#include <optional>
#include <algorithm>
#include <string_view>

namespace mdnspp::detail {

struct service_names
{
    dns_name instance;
    dns_name type;
    dns_name host;
};

inline expected<std::string, mdns_error> normalize_service_type(std::string_view service_type)
{
    std::string type{service_type};
    if(!type.empty() && type.back() == '.')
        type.pop_back();
    if(!parse_service_type_checked(type).has_value())
        type += ".local";
    if(auto checked = parse_service_type_checked(type); !checked.has_value())
        return unexpected(checked.error());
    type.push_back('.');
    return type;
}

// RFC 6763 §4.3: dots and backslashes inside an instance name are content,
// not label separators.
inline std::string instance_fqdn(std::string_view instance, const std::string &type)
{
    std::string name;
    for(char c : instance)
        append_escaped_label_byte(name, c);
    name.push_back('.');
    return name + type;
}

inline std::string override_hostname_fqdn(std::string host)
{
    if(!host.empty() && host.back() == '.')
        host.pop_back();
    constexpr std::string_view suffix = ".local";
    const bool suffixed = host.size() > suffix.size()
        && std::equal(suffix.begin(), suffix.end(), host.end() - suffix.size(),
                      [](char a, char b) { return a == dns_name::ascii_fold(b); });
    if(!suffixed)
        host += suffix;
    host.push_back('.');
    return host;
}

inline std::string os_hostname_fqdn()
{
    std::string label = os_hostname();
    if(auto dot = label.find('.'); dot != std::string::npos)
        label.resize(dot);
    std::string host;
    for(char c : label)
        append_escaped_label_byte(host, c);
    return host + ".local.";
}

inline expected<service_names, mdns_error> parse_service_names(
    std::string_view instance, std::string_view service_type, std::optional<std::string> hostname)
{
    auto type = normalize_service_type(service_type);
    if(!type.has_value())
        return unexpected(type.error());
    auto type_name = dns_name::parse(*type);
    if(!type_name.has_value())
        return unexpected(type_name.error());
    auto instance_name = dns_name::parse(instance_fqdn(instance, *type));
    if(!instance_name.has_value())
        return unexpected(instance_name.error());
    auto host_name = dns_name::parse(hostname ? override_hostname_fqdn(std::move(*hostname)) : os_hostname_fqdn());
    if(!host_name.has_value())
        return unexpected(host_name.error());
    return service_names{std::move(*instance_name), std::move(*type_name), std::move(*host_name)};
}

}

#endif
