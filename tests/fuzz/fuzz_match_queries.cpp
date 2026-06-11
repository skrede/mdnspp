#include "mdnspp/service_info.h"
#include "mdnspp/service_options.h"

#include "mdnspp/detail/server_query_match.h"
#include "mdnspp/detail/server_response_aggregation.h"

#include <cstddef>
#include <cstdint>
#include <span>

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
    info.subtypes.push_back("alpha");
    return info;
}

}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    static const mdnspp::service_info info = make_info();
    static const mdnspp::service_options opts{};

    auto buf = std::span<const std::byte>(reinterpret_cast<const std::byte *>(data), size);

    auto match = mdnspp::detail::match_queries(buf, info, opts);
    auto plan = mdnspp::detail::plan_answers(match.matched, info);
    (void)plan;
    auto rebuilt = mdnspp::detail::rebuild_question_section(buf);
    (void)rebuilt;

    return 0;
}
