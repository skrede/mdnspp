#if defined(MDNSPP_HAS_ASIO)

#include "helpers.h"
#include "asio_rigs.h"

#include "support/alloc_counter.h"

#include <catch2/catch_test_macros.hpp>

#include <span>
#include <cstddef>
#include <cstdint>

namespace {

constexpr int window_cycles = 50;

template <typename Rig>
uint64_t allocations_over_window(Rig &rig, std::span<const std::byte> payload)
{
    rig.cycle(payload);
    mdnspp::test_support::reset_allocation_count();
    for(int i = 0; i < window_cycles; ++i)
        rig.cycle(payload);
    return mdnspp::test_support::allocation_count();
}

void require_no_more_than_plain(const loopback_family &family)
{
    const plain_bytes plaintext(200, std::byte{0x5A});
    plain_rig plain(family);
    const uint64_t baseline = allocations_over_window(plain, plaintext);
    encrypted_rig encrypted(family);
    const uint64_t measured = allocations_over_window(encrypted, plaintext);
    CHECK(plain.delivered() == window_cycles + 1);
    CHECK(encrypted.delivered() == window_cycles + 1);
    INFO("baseline allocations " << baseline << ", encrypted allocations " << measured);
    REQUIRE(measured <= baseline);
}

}

TEST_CASE("encrypted send and deliver over the asio socket allocates no more than a plain asio receive loop",
          "[encrypted_socket][alloc][asio_socket]")
{
    require_no_more_than_plain(ipv4_loopback());
}

TEST_CASE("encrypted send and deliver over the asio socket on IPv6 loopback allocates no more than a plain asio "
          "receive loop",
          "[encrypted_socket][alloc][asio_socket]")
{
    require_no_more_than_plain(ipv6_loopback());
}

#endif
