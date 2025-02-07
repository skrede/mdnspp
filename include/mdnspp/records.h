#ifndef MDNSPP_RECORDS_H
#define MDNSPP_RECORDS_H

#include <string>
#include <memory>
#include <optional>
#include <iostream>
#include <functional>

#include <mdns.h>

namespace mdnspp {

struct service_txt
{
    std::string key;
    std::optional<std::string> value;
};

struct record_t
{
    record_t(mdns_record_type rtype, mdns_entry_type etype)
        : etype(etype)
        , rtype(rtype)
    {
    }

    virtual ~record_t() = default;
    uint32_t ttl = 0u;
    uint32_t length = 0u;
    uint16_t rclass = 0u;
    mdns_entry_type etype;
    mdns_record_type rtype;
    std::string name;
    std::string sender_address;
};

typedef std::function<bool(const std::shared_ptr<mdnspp::record_t> &)> record_filter;

struct record_ptr_t : public record_t
{
    explicit record_ptr_t(mdns_entry_type etype)
        : record_t(MDNS_RECORDTYPE_PTR, etype)
    {
    }

    std::string ptr_name;
};

struct record_srv_t : public record_t
{
    explicit record_srv_t(mdns_entry_type etype)
        : record_t(MDNS_RECORDTYPE_SRV, etype)
    {
    }

    uint16_t port;
    uint16_t weight;
    uint16_t priority;
    std::string srv_name;
};

struct record_a_t : public record_t
{
    explicit record_a_t(mdns_entry_type etype)
        : record_t(MDNS_RECORDTYPE_A, etype)
    {
    }

    sockaddr_in addr;
    std::string address_string;
};

struct record_aaaa_t : public record_t
{
    explicit record_aaaa_t(mdns_entry_type etype)
        : record_t(MDNS_RECORDTYPE_AAAA, etype)
    {
    }

    sockaddr_in6 addr;
    std::string address_string;
};

struct record_txt_t : public record_t
{
    explicit record_txt_t(mdns_entry_type etype)
        : record_t(MDNS_RECORDTYPE_TXT, etype)
    {
    }

    std::string key;
    std::optional<std::string> value;
};

inline std::string entry_type_name(mdns_entry_type type)
{
    switch(type)
    {
        case MDNS_ENTRYTYPE_QUESTION:
            return "QUESTION";
        case MDNS_ENTRYTYPE_ANSWER:
            return "ANSWER";
        case MDNS_ENTRYTYPE_AUTHORITY:
            return "AUTHORITY";
        default:
            return "ADDITIONAL";
    }
}

inline std::string record_type_name(mdns_record_type type)
{
    switch(type)
    {
        case MDNS_RECORDTYPE_PTR:
            return "PTR";
        case MDNS_RECORDTYPE_A:
            return "A";
        case MDNS_RECORDTYPE_AAAA:
            return "AAAA";
        case MDNS_RECORDTYPE_TXT:
            return "TXT";
        case MDNS_RECORDTYPE_SRV:
            return "SRV";
        case MDNS_RECORDTYPE_ANY:
            return "ANY";
        default:
            return "IGNORE";
    }
}

inline std::ostream &operator<<(std::ostream &str, const record_ptr_t &record)
{
    str << record.sender_address << ": " << entry_type_name(record.etype) << " PTR " << record.name << record.ptr_name << " rclass 0x" << std::hex << record.rclass << std::dec << " ttl " << record.ttl << " length " << record.length;
    return str;
}

inline std::ostream &operator<<(std::ostream &str, const record_srv_t &record)
{
    str << record.sender_address << ": " << entry_type_name(record.etype) << " SRV " << record.name << record.srv_name << " rclass 0x" << std::hex << record.rclass << std::dec << " ttl " << record.ttl << " length " << record.length;
    return str;
}

inline std::ostream &operator<<(std::ostream &str, const record_a_t &record)
{
    str << record.sender_address << ": " << entry_type_name(record.etype) << " A " << record.name << record.address_string << " rclass 0x" << std::hex << record.rclass << std::dec << " ttl " << record.ttl << " length " << record.length;
    return str;
}

inline std::ostream &operator<<(std::ostream &str, const record_aaaa_t &record)
{
    str << record.sender_address << ": " << entry_type_name(record.etype) << " AAAA " << record.name << record.address_string << " rclass 0x" << std::hex << record.rclass << std::dec << " ttl " << record.ttl << " length " << record.length;
    return str;
}

inline std::ostream &operator<<(std::ostream &str, const record_txt_t &record)
{
    str << record.sender_address << ": " << entry_type_name(record.etype) << " TXT " << record.key;
    if(record.value.has_value())
        str << "=" << *record.value;
    str << " rclass 0x" << std::hex << record.rclass << std::dec << " ttl " << record.ttl << " length " << record.length;
    return str;
}

inline std::ostream &operator<<(std::ostream &str, const record_t &record)
{
    str << record.sender_address << ": " << entry_type_name(record.etype) << " " << record_type_name(record.rtype) << " " << record.name << " rclass 0x" << std::hex << record.rclass << std::dec << " ttl " << record.ttl << " length " << record.length;
    return str;
}

}

#endif
