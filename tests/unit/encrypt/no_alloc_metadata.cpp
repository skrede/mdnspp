#include "support/alloc_counter.h"

#include "mdnspp/policy.h"

#include "mdnspp/detail/recv_datagram.h"

#include <catch2/catch_test_macros.hpp>

#include <string>
#include <cstdint>

namespace {

sockaddr_storage make_v6(const char *text, uint16_t port)
{
    sockaddr_storage storage{};
    auto &sa = reinterpret_cast<sockaddr_in6 &>(storage);
    sa.sin6_family = AF_INET6;
    sa.sin6_port = htons(port);
    ::inet_pton(AF_INET6, text, &sa.sin6_addr);
    return storage;
}

uint64_t allocations_filling(const sockaddr_storage &sender, mdnspp::recv_metadata &out)
{
    const mdnspp::detail::ancillary_data ancillary{};
    mdnspp::detail::fill_metadata(out, sender, ancillary);
    mdnspp::test_support::reset_allocation_count();
    for(int i = 0; i < 100; ++i)
        mdnspp::detail::fill_metadata(out, sender, ancillary);
    return mdnspp::test_support::allocation_count();
}

}

TEST_CASE("filling the receive metadata for a long IPv6 sender allocates nothing", "[alloc][metadata]")
{
    const char *text = "2001:db8:aaaa:bbbb:cccc:dddd:eeee:ffff";
    mdnspp::recv_metadata meta = mdnspp::detail::reserved_metadata();
    const uint64_t count = allocations_filling(make_v6(text, 5353), meta);
    CHECK(meta.sender.address == text);
    CHECK(meta.sender.port == 5353);
    REQUIRE(count == 0);
}

TEST_CASE("filling the receive metadata for an IPv4-mapped IPv6 sender allocates nothing", "[alloc][metadata]")
{
    const char *text = "::ffff:192.168.100.200";
    mdnspp::recv_metadata meta = mdnspp::detail::reserved_metadata();
    const uint64_t count = allocations_filling(make_v6(text, 5353), meta);
    CHECK(meta.sender.address == text);
    CHECK(meta.sender.port == 5353);
    REQUIRE(count == 0);
}
