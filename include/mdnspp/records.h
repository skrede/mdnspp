#ifndef MDNSPP_RECORDS_H
#define MDNSPP_RECORDS_H

#include <variant>
#include <string>
#include <cstdint>
#include <optional>
#include <ostream>

namespace mdnspp {

struct service_txt
{
    std::string              key;
    std::optional<std::string> value;
};

struct record_ptr
{
    std::string name;
    uint32_t    ttl{0};
    uint16_t    rclass{0};
    uint32_t    length{0};
    std::string sender_address;
    std::string ptr_name;
};

struct record_srv
{
    std::string name;
    uint32_t    ttl{0};
    uint16_t    rclass{0};
    uint32_t    length{0};
    std::string sender_address;
    uint16_t    port{0};
    uint16_t    weight{0};
    uint16_t    priority{0};
    std::string srv_name;
};

struct record_a
{
    std::string name;
    uint32_t    ttl{0};
    uint16_t    rclass{0};
    uint32_t    length{0};
    std::string sender_address;
    std::string address_string;  // "192.168.1.1" — no sockaddr_in
};

struct record_aaaa
{
    std::string name;
    uint32_t    ttl{0};
    uint16_t    rclass{0};
    uint32_t    length{0};
    std::string sender_address;
    std::string address_string;  // "fe80::1" — no sockaddr_in6
};

struct record_txt
{
    std::string              name;
    uint32_t                 ttl{0};
    uint16_t                 rclass{0};
    uint32_t                 length{0};
    std::string              sender_address;
    std::string              key;
    std::optional<std::string> value;
};

using mdns_record_variant = std::variant<
    record_ptr,
    record_srv,
    record_a,
    record_aaaa,
    record_txt
>;

inline std::ostream& operator<<(std::ostream& str, const record_ptr& r)
{
    str << r.sender_address << ": PTR " << r.name << " -> " << r.ptr_name
        << " rclass 0x" << std::hex << r.rclass << std::dec
        << " ttl " << r.ttl << " length " << r.length;
    return str;
}

inline std::ostream& operator<<(std::ostream& str, const record_srv& r)
{
    str << r.sender_address << ": SRV " << r.name << " -> " << r.srv_name
        << " port " << r.port << " weight " << r.weight << " priority " << r.priority
        << " rclass 0x" << std::hex << r.rclass << std::dec
        << " ttl " << r.ttl << " length " << r.length;
    return str;
}

inline std::ostream& operator<<(std::ostream& str, const record_a& r)
{
    str << r.sender_address << ": A " << r.name << " -> " << r.address_string
        << " rclass 0x" << std::hex << r.rclass << std::dec
        << " ttl " << r.ttl << " length " << r.length;
    return str;
}

inline std::ostream& operator<<(std::ostream& str, const record_aaaa& r)
{
    str << r.sender_address << ": AAAA " << r.name << " -> " << r.address_string
        << " rclass 0x" << std::hex << r.rclass << std::dec
        << " ttl " << r.ttl << " length " << r.length;
    return str;
}

inline std::ostream& operator<<(std::ostream& str, const record_txt& r)
{
    str << r.sender_address << ": TXT " << r.name << " " << r.key;
    if(r.value.has_value())
        str << "=" << *r.value;
    str << " rclass 0x" << std::hex << r.rclass << std::dec
        << " ttl " << r.ttl << " length " << r.length;
    return str;
}

} // namespace mdnspp

#endif // MDNSPP_RECORDS_H
