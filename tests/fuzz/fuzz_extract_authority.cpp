#include "mdnspp/service_info.h"

#include "mdnspp/detail/dns_query.h"
#include "mdnspp/detail/dns_enums.h"
#include "mdnspp/detail/server_probe_announce.h"

#include <cstddef>
#include <cstdint>
#include <span>
#include <utility>
#include <vector>

namespace {

std::vector<mdnspp::detail::tiebreak_record> make_our_records()
{
    mdnspp::service_info info;
    info.service_name = "Fuzzer._fuzz._tcp.local.";
    info.service_type = "_fuzz._tcp.local.";
    info.hostname = "fuzzhost.local.";
    info.port = 8080;
    info.address_ipv4 = "192.168.1.42";
    info.address_ipv6 = "fe80::1";
    info.txt_records.push_back({"key", "value"});

    std::vector<mdnspp::detail::tiebreak_record> records;
    for(auto &rec : mdnspp::detail::build_proposed_records(info))
        records.push_back(mdnspp::detail::tiebreak_record{
            mdnspp::detail::to_underlying(mdnspp::dns_class::in),
            mdnspp::detail::to_underlying(rec.rtype),
            std::move(rec.rdata)});
    return records;
}

}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    static const std::vector<mdnspp::detail::tiebreak_record> ours = make_our_records();

    auto buf = std::span<const std::byte>(reinterpret_cast<const std::byte *>(data), size);

    auto theirs = mdnspp::detail::extract_authority_records(buf);
    auto cmp = mdnspp::detail::compare_record_sets(ours, std::move(theirs));
    (void)cmp;

    return 0;
}
