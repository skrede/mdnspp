#ifndef HPP_GUARD_MDNSPP_MDNS_ERROR_H
#define HPP_GUARD_MDNSPP_MDNS_ERROR_H

#include <string>
#include <cstdint>
#include <system_error>

namespace mdnspp {

enum class mdns_error : uint32_t
{
    socket_error    = 1,
    no_interfaces   = 2,
    parse_error     = 3,
    send_failed     = 4,
    receive_failed  = 5,
    timeout         = 6,
    not_implemented = 7,
    probe_conflict  = 8
};

inline const std::error_category &mdns_error_category() noexcept
{
    struct category : std::error_category
    {
        const char *name() const noexcept override { return "mdns"; }

        std::string message(int ev) const override
        {
            switch(static_cast<mdns_error>(ev))
            {
            case mdns_error::socket_error: return "socket error";
            case mdns_error::no_interfaces: return "no network interfaces available";
            case mdns_error::parse_error: return "DNS parse error";
            case mdns_error::send_failed: return "send failed";
            case mdns_error::receive_failed: return "receive failed";
            case mdns_error::timeout: return "operation timed out";
            case mdns_error::not_implemented: return "not implemented";
            case mdns_error::probe_conflict: return "name conflict detected during probing";
            }
            return "unknown mdns error";
        }
    };

    static const category instance;
    return instance;
}

inline std::error_code make_error_code(mdns_error e)
{
    return {static_cast<int>(e), mdns_error_category()};
}

}

template <>
struct std::is_error_code_enum<mdnspp::mdns_error> : std::true_type
{
};

#endif
