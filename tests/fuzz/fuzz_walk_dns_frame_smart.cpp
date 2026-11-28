#include "mdnspp/endpoint.h"

#include "mdnspp/detail/dns_read.h"
#include "mdnspp/detail/dns_frame.h"

#include <fuzzer/FuzzedDataProvider.h>

#include <span>
#include <vector>
#include <cstddef>
#include <cstdint>

namespace {

// A plausible DNS header with bounded record counts, followed by the remaining input as the body.
std::vector<std::byte> build_frame(FuzzedDataProvider &fdp)
{
    uint16_t id = fdp.ConsumeIntegral<uint16_t>();
    uint16_t flags = fdp.ConsumeIntegral<uint16_t>();
    uint16_t qdcount = fdp.ConsumeIntegralInRange<uint16_t>(0, 8);
    uint16_t ancount = fdp.ConsumeIntegralInRange<uint16_t>(0, 8);
    uint16_t nscount = fdp.ConsumeIntegralInRange<uint16_t>(0, 4);
    uint16_t arcount = fdp.ConsumeIntegralInRange<uint16_t>(0, 4);

    std::vector<std::byte> frame;
    frame.reserve(12 + fdp.remaining_bytes());
    mdnspp::detail::push_u16_be(frame, id);
    mdnspp::detail::push_u16_be(frame, flags);
    mdnspp::detail::push_u16_be(frame, qdcount);
    mdnspp::detail::push_u16_be(frame, ancount);
    mdnspp::detail::push_u16_be(frame, nscount);
    mdnspp::detail::push_u16_be(frame, arcount);

    auto body = fdp.ConsumeRemainingBytes<uint8_t>();
    for(uint8_t b : body)
        frame.push_back(static_cast<std::byte>(b));
    return frame;
}

}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    std::vector<std::byte> frame = build_frame(fdp);

    mdnspp::endpoint sender{};
    mdnspp::detail::walk_dns_frame(std::span<const std::byte>(frame), sender, [](auto &&) {});

    return 0;
}
