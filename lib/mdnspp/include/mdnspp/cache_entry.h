#ifndef HPP_GUARD_MDNSPP_CACHE_ENTRY_H
#define HPP_GUARD_MDNSPP_CACHE_ENTRY_H

#include "mdnspp/records.h"
#include "mdnspp/endpoint.h"

#include <chrono>
#include <cstdint>

namespace mdnspp {

struct cache_entry
{
    mdns_record_variant record;
    endpoint origin;
    bool cache_flush{false};
    uint32_t wire_ttl{0};
    std::chrono::nanoseconds ttl_remaining{};
};

}

#endif
