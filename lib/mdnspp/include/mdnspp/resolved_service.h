#ifndef HPP_GUARD_MDNSPP_RESOLVED_SERVICE_H
#define HPP_GUARD_MDNSPP_RESOLVED_SERVICE_H

#include "mdnspp/records.h"
#include "mdnspp/network_interface.h"

#include <span>
#include <chrono>
#include <string>
#include <vector>
#include <cstdint>

namespace mdnspp {

struct resolved_service
{
    dns_name instance_name;
    dns_name hostname;
    uint16_t port{0};
    std::vector<service_txt> txt_entries;
    std::vector<std::string> ipv4_addresses;
    std::vector<std::string> ipv6_addresses;
    std::chrono::nanoseconds ttl_remaining{};
    uint32_t wire_ttl{0};
    network_interface source_interface{};
};

inline std::vector<resolved_service> aggregate(std::span<const mdns_record_variant> records);

inline std::vector<resolved_service> aggregate(const std::vector<mdns_record_variant> &records)
{
    return aggregate(std::span<const mdns_record_variant>{records});
}

}

#include "mdnspp/detail/service_aggregation.h"

#endif
