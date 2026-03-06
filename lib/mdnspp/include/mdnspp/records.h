#ifndef HPP_GUARD_MDNSPP_RECORDS_H
#define HPP_GUARD_MDNSPP_RECORDS_H

#include "mdnspp/detail/dns_enums.h"

#include <string>
#include <vector>
#include <cstdint>
#include <iosfwd>
#include <variant>
#include <optional>

namespace mdnspp {

struct service_txt
{
    std::string key;
    std::optional<std::string> value;
};

struct record_ptr
{
    std::string name;
    uint32_t ttl{0};
    dns_class rclass{dns_class::none};
    uint32_t length{0};
    std::string sender_address;
    std::string ptr_name;
};

struct record_srv
{
    std::string name;
    uint32_t ttl{0};
    dns_class rclass{dns_class::none};
    uint32_t length{0};
    std::string sender_address;
    uint16_t port{0};
    uint16_t weight{0};
    uint16_t priority{0};
    std::string srv_name;
};

struct record_a
{
    std::string name;
    uint32_t ttl{0};
    dns_class rclass{dns_class::none};
    uint32_t length{0};
    std::string sender_address;
    std::string address_string; // "192.168.1.1" — no sockaddr_in
};

struct record_aaaa
{
    std::string name;
    uint32_t ttl{0};
    dns_class rclass{dns_class::none};
    uint32_t length{0};
    std::string sender_address;
    std::string address_string; // "fe80::1" — no sockaddr_in6
};

struct record_txt
{
    std::string name;
    uint32_t ttl{0};
    dns_class rclass{dns_class::none};
    uint32_t length{0};
    std::string sender_address;
    std::vector<service_txt> entries;
};

using mdns_record_variant = std::variant<
    record_ptr,
    record_srv,
    record_a,
    record_aaaa,
    record_txt
>;

template<typename CharT, typename Traits>
std::basic_ostream<CharT, Traits> &operator<<(std::basic_ostream<CharT, Traits> &str, const record_ptr &r)
{
    str << r.sender_address << ": PTR " << r.name << " -> " << r.ptr_name
        << " rclass " << to_string(r.rclass)
        << " ttl " << r.ttl << " length " << r.length;
    return str;
}

template<typename CharT, typename Traits>
std::basic_ostream<CharT, Traits> &operator<<(std::basic_ostream<CharT, Traits> &str, const record_srv &r)
{
    str << r.sender_address << ": SRV " << r.name << " -> " << r.srv_name
        << " port " << r.port << " weight " << r.weight << " priority " << r.priority
        << " rclass " << to_string(r.rclass)
        << " ttl " << r.ttl << " length " << r.length;
    return str;
}

template<typename CharT, typename Traits>
std::basic_ostream<CharT, Traits> &operator<<(std::basic_ostream<CharT, Traits> &str, const record_a &r)
{
    str << r.sender_address << ": A " << r.name << " -> " << r.address_string
        << " rclass " << to_string(r.rclass)
        << " ttl " << r.ttl << " length " << r.length;
    return str;
}

template<typename CharT, typename Traits>
std::basic_ostream<CharT, Traits> &operator<<(std::basic_ostream<CharT, Traits> &str, const record_aaaa &r)
{
    str << r.sender_address << ": AAAA " << r.name << " -> " << r.address_string
        << " rclass " << to_string(r.rclass)
        << " ttl " << r.ttl << " length " << r.length;
    return str;
}

template<typename CharT, typename Traits>
std::basic_ostream<CharT, Traits> &operator<<(std::basic_ostream<CharT, Traits> &str, const record_txt &r)
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
