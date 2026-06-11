#include "mdnspp/endpoint.h"
#include "mdnspp/service_info.h"
#include "mdnspp/service_options.h"

#include "mdnspp/detail/dns_frame.h"
#include "mdnspp/detail/server_known_answer.h"

#include <fuzzer/FuzzedDataProvider.h>

#include <cstddef>
#include <cstdint>
#include <span>
#include <utility>
#include <vector>

namespace {

mdnspp::service_info make_info()
{
    mdnspp::service_info info;
    info.service_name = "Fuzzer._fuzz._tcp.local.";
    info.service_type = "_fuzz._tcp.local.";
    info.hostname = "fuzzhost.local.";
    info.port = 8080;
    info.address_ipv4 = "192.168.1.42";
    info.address_ipv6 = "fe80::1";
    info.txt_records.push_back({"key", "value"});
    return info;
}

}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    static const mdnspp::service_info info = make_info();
    static const mdnspp::service_options opts{};
    static const mdnspp::detail::ka_thresholds thresholds =
        mdnspp::detail::make_ka_thresholds(opts, 0.5);

    FuzzedDataProvider fdp(data, size);
    const size_t offset = fdp.ConsumeIntegralInRange<size_t>(0, 64);
    auto bytes = fdp.ConsumeRemainingBytes<uint8_t>();
    auto buf = std::span<const std::byte>(
        reinterpret_cast<const std::byte *>(bytes.data()), bytes.size());

    auto mask = mdnspp::detail::parse_known_answers(buf, offset, info, thresholds);
    (void)mask;

    // TC accumulation path: suppression over parsed records (RFC 6762 §7.2).
    std::vector<mdnspp::mdns_record_variant> records;
    mdnspp::detail::walk_dns_frame(buf, mdnspp::endpoint{},
        [&](mdnspp::mdns_record_variant rv) { records.push_back(std::move(rv)); });
    auto tc_mask = mdnspp::detail::suppress_from_records(records, info, thresholds);
    (void)tc_mask;

    return 0;
}
