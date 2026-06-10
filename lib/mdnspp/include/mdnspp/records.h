#ifndef HPP_GUARD_MDNSPP_RECORDS_H
#define HPP_GUARD_MDNSPP_RECORDS_H

#include "mdnspp/dns_name.h"
#include "mdnspp/detail/dns_enums.h"

#include <string>
#include <vector>
#include <cstdint>
#include <ostream>
#include <variant>
#include <optional>
#include <type_traits>

namespace mdnspp {

struct service_txt
{
    std::string key;
    std::optional<std::string> value;

    bool operator==(const service_txt &) const = default;
};

struct record_ptr
{
    static constexpr dns_type rtype = dns_type::ptr;

    dns_name name;
    uint32_t ttl{0};
    dns_class rclass{dns_class::none};
    uint32_t length{0};
    std::string sender_address;
    bool cache_flush{false};
    dns_name ptr_name;

    bool operator==(const record_ptr &) const = default;
};

struct record_srv
{
    static constexpr dns_type rtype = dns_type::srv;

    dns_name name;
    uint32_t ttl{0};
    dns_class rclass{dns_class::none};
    uint32_t length{0};
    std::string sender_address;
    bool cache_flush{false};
    uint16_t port{0};
    uint16_t weight{0};
    uint16_t priority{0};
    dns_name srv_name;

    bool operator==(const record_srv &) const = default;
};

struct record_a
{
    static constexpr dns_type rtype = dns_type::a;

    dns_name name;
    uint32_t ttl{0};
    dns_class rclass{dns_class::none};
    uint32_t length{0};
    std::string sender_address;
    bool cache_flush{false};
    std::string address_string; // "192.168.1.1" — no sockaddr_in

    bool operator==(const record_a &) const = default;
};

struct record_aaaa
{
    static constexpr dns_type rtype = dns_type::aaaa;

    dns_name name;
    uint32_t ttl{0};
    dns_class rclass{dns_class::none};
    uint32_t length{0};
    std::string sender_address;
    bool cache_flush{false};
    std::string address_string; // "fe80::1" — no sockaddr_in6

    bool operator==(const record_aaaa &) const = default;
};

struct record_txt
{
    static constexpr dns_type rtype = dns_type::txt;

    dns_name name;
    uint32_t ttl{0};
    dns_class rclass{dns_class::none};
    uint32_t length{0};
    std::string sender_address;
    bool cache_flush{false};
    std::vector<service_txt> entries;

    bool operator==(const record_txt &) const = default;
};

using mdns_record_variant = std::variant<
    record_ptr,
    record_srv,
    record_a,
    record_aaaa,
    record_txt
>;

/// dns_type tag of the alternative currently held by the variant.
[[nodiscard]] inline dns_type record_type(const mdns_record_variant &rec)
{
    return std::visit([](const auto &r) { return std::remove_cvref_t<decltype(r)>::rtype; }, rec);
}

inline std::ostream &operator<<(std::ostream &str, const record_ptr &r)
{
    str << r.sender_address << ": PTR " << r.name << " -> " << r.ptr_name
        << " rclass " << to_string(r.rclass)
        << " ttl " << r.ttl << " length " << r.length;
    return str;
}

inline std::ostream &operator<<(std::ostream &str, const record_srv &r)
{
    str << r.sender_address << ": SRV " << r.name << " -> " << r.srv_name
        << " port " << r.port << " weight " << r.weight << " priority " << r.priority
        << " rclass " << to_string(r.rclass)
        << " ttl " << r.ttl << " length " << r.length;
    return str;
}

inline std::ostream &operator<<(std::ostream &str, const record_a &r)
{
    str << r.sender_address << ": A " << r.name << " -> " << r.address_string
        << " rclass " << to_string(r.rclass)
        << " ttl " << r.ttl << " length " << r.length;
    return str;
}

inline std::ostream &operator<<(std::ostream &str, const record_aaaa &r)
{
    str << r.sender_address << ": AAAA " << r.name << " -> " << r.address_string
        << " rclass " << to_string(r.rclass)
        << " ttl " << r.ttl << " length " << r.length;
    return str;
}

inline std::ostream &operator<<(std::ostream &str, const record_txt &r)
{
    str << r.sender_address << ": TXT " << r.name;
    for(const auto &e : r.entries)
    {
        str << " " << e.key;
        if(e.value.has_value())
            str << "=" << *e.value;
    }
    str << " rclass " << to_string(r.rclass)
        << " ttl " << r.ttl << " length " << r.length;
    return str;
}

}

#endif
