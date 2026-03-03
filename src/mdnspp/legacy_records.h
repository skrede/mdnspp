#ifndef MDNSPP_LEGACY_RECORDS_H
#define MDNSPP_LEGACY_RECORDS_H

// legacy_records.h — TRANSITIONAL HEADER (Phase 1 bridge)
// Provides the old C-based record types used by record_parser and record_builder.
// These types are private implementation details in src/mdnspp/ only.
// Phase 3/6 will migrate these to the new variant-based system from records.h.
// Do NOT include this header from public headers in include/mdnspp/.

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

using record_filter = std::function<bool(const std::shared_ptr<mdnspp::record_t> &)>;

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

    uint16_t port{0};
    uint16_t weight{0};
    uint16_t priority{0};
    std::string srv_name;
};

struct record_a_t : public record_t
{
    explicit record_a_t(mdns_entry_type etype)
        : record_t(MDNS_RECORDTYPE_A, etype)
    {
    }

    sockaddr_in addr{};
    std::string address_string;
};

struct record_aaaa_t : public record_t
{
    explicit record_aaaa_t(mdns_entry_type etype)
        : record_t(MDNS_RECORDTYPE_AAAA, etype)
    {
    }

    sockaddr_in6 addr{};
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

}

#endif
