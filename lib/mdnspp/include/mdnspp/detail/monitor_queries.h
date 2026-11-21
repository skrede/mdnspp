#ifndef HPP_GUARD_MDNSPP_DETAIL_MONITOR_QUERIES_H
#define HPP_GUARD_MDNSPP_DETAIL_MONITOR_QUERIES_H

#include "mdnspp/detail/dns_read.h"
#include "mdnspp/detail/dns_enums.h"
#include "mdnspp/detail/dns_query.h"

#include "mdnspp/records.h"
#include "mdnspp/cache_entry.h"

#include <array>
#include <chrono>
#include <vector>
#include <cstddef>
#include <cstdint>
#include <string_view>

namespace mdnspp::detail {

// Known answers of a query (RFC 6762 section 7.1): only records whose remaining TTL exceeds the
// suppression threshold, so stale records are not advertised.
inline std::vector<mdns_record_variant> select_known_answers(const std::vector<cache_entry> &entries,
                                                             double fraction)
{
    std::vector<mdns_record_variant> known_answers;
    for(const auto &e : entries)
    {
        auto threshold = std::chrono::duration_cast<std::chrono::nanoseconds>(
            std::chrono::duration<double>(e.wire_ttl * fraction));
        if(e.ttl_remaining > threshold)
            known_answers.push_back(e.record);
    }
    return known_answers;
}

// Refreshing an instance queries SRV, TXT (which would otherwise silently expire) and both address
// types (RFC 6762 section 5.2), aggregated into one multi-question message (section 5). Empty when
// the name does not encode.
inline std::vector<std::byte> build_instance_query(std::string_view inst_name)
{
    auto encoded_name = encode_dns_name(inst_name);
    if(!encoded_name.has_value())
        return {};
    const auto &encoded = *encoded_name;

    static constexpr std::array<dns_type, 4> qtypes{dns_type::srv, dns_type::txt,
                                                    dns_type::a, dns_type::aaaa};

    std::vector<std::byte> packet;
    packet.reserve(12 + (encoded.size() + 4) * qtypes.size());
    append_query_header(packet, static_cast<uint16_t>(qtypes.size()), 0);
    for(dns_type qtype : qtypes)
        append_question(packet, encoded, qtype, 0x0001);
    return packet;
}

}

#endif
