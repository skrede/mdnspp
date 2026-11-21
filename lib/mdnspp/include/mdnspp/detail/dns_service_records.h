#ifndef HPP_GUARD_MDNSPP_DETAIL_DNS_SERVICE_RECORDS_H
#define HPP_GUARD_MDNSPP_DETAIL_DNS_SERVICE_RECORDS_H

#include "mdnspp/detail/dns_read.h"
#include "mdnspp/detail/dns_write.h"
#include "mdnspp/detail/dns_record_encode.h"

#include "mdnspp/service_info.h"

#include <vector>
#include <cstddef>
#include <utility>

namespace mdnspp::detail {

// Empty rdata_a / rdata_aaaa: the address is unset or failed to encode (the server reports address errors
// separately). valid is false when a name fails to encode.
struct service_wire_records
{
    std::vector<std::byte> name_service_type;
    std::vector<std::byte> name_service_name;
    std::vector<std::byte> name_hostname;
    std::vector<std::byte> rdata_ptr;
    std::vector<std::byte> rdata_srv;
    std::vector<std::byte> rdata_txt;
    std::vector<std::byte> rdata_a;
    std::vector<std::byte> rdata_aaaa;
    bool valid{false};
};

inline void encode_service_addresses(service_wire_records &w, const mdnspp::service_info &info)
{
    if(info.address_ipv4.has_value())
    {
        if(auto enc = encode_ipv4(*info.address_ipv4); enc.has_value())
            w.rdata_a = std::move(*enc);
    }
    if(info.address_ipv6.has_value())
    {
        if(auto enc = encode_ipv6(*info.address_ipv6); enc.has_value())
            w.rdata_aaaa = std::move(*enc);
    }
}

inline service_wire_records encode_service_records(const mdnspp::service_info &info)
{
    service_wire_records w;
    auto name_service_type = encode_dns_name(info.service_type);
    auto name_service_name = encode_dns_name(info.service_name);
    auto name_hostname = encode_dns_name(info.hostname);
    if(!name_service_type.has_value() || !name_service_name.has_value() || !name_hostname.has_value())
        return w;
    w.name_service_type = std::move(*name_service_type);
    w.name_service_name = std::move(*name_service_name);
    w.name_hostname = std::move(*name_hostname);
    w.rdata_ptr = w.name_service_name;
    w.rdata_srv = encode_srv_rdata(info.priority, info.weight, info.port, w.name_hostname);
    w.rdata_txt = encode_txt_records(info.txt_records);
    encode_service_addresses(w, info);
    w.valid = true;
    return w;
}

}

#endif
