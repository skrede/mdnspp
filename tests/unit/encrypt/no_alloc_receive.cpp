#include "helpers.h"

#include "support/alloc_counter.h"

#include "mdnspp/encrypt/encrypted_policy.h"

#include "mdnspp/detail/recv_loop.h"

#include "mdnspp/testing/mock_policy.h"

#include <catch2/catch_test_macros.hpp>

#include <span>
#include <vector>
#include <cstddef>
#include <cstdint>

namespace {

using policy = mdnspp::encrypt::encrypted_policy<mdnspp::testing::mock_policy>;

struct delivery
{
    mdnspp::endpoint from;
    plain_bytes packet;
};

struct receive_rig
{
    mdnspp::testing::mock_executor ex;
    test_socket receiver;
    mdnspp::testing::mock_timer timer;
    uint64_t delivered;
    mdnspp::detail::recv_loop<policy> loop;

    receive_rig()
        : ex{}
        , receiver(ex, make_test_opts(std::byte{0x42}, 2))
        , timer(ex)
        , delivered(0)
        , loop(receiver, timer, mdnspp::detail::infinite_silence_timeout,
               [this](const mdnspp::recv_metadata &, std::span<std::byte>) -> bool
               {
                   ++delivered;
                   return true;
               },
               [] {})
    {
        loop.start();
    }
};

std::vector<delivery> seal_deliveries(const mdnspp::encrypt::encrypt_socket_options &sender_opts, int count)
{
    mdnspp::testing::mock_executor ex;
    test_socket sender(ex, sender_opts);
    std::vector<delivery> out;
    const plain_bytes plaintext(200, std::byte{0x5A});
    for(int i = 0; i < count; ++i)
        out.push_back({mdnspp::endpoint{"192.0.2.1", 5353}, sealed_by(sender, plaintext)});
    return out;
}

uint64_t allocations_over_window(const mdnspp::encrypt::encrypt_socket_options &sender_opts, uint64_t &delivered)
{
    auto packets = seal_deliveries(sender_opts, 101);
    receive_rig rig;
    rig.receiver.inner().inject_receive(std::move(packets[0].from), std::move(packets[0].packet));
    mdnspp::test_support::reset_allocation_count();
    for(std::size_t i = 1; i < packets.size(); ++i)
        rig.receiver.inner().inject_receive(std::move(packets[i].from), std::move(packets[i].packet));
    const uint64_t count = mdnspp::test_support::allocation_count();
    delivered = rig.delivered;
    return count;
}

}

TEST_CASE("steady-state encrypted receive-deliver allocates nothing", "[encrypted_socket][alloc]")
{
    uint64_t delivered = 0;
    const uint64_t count = allocations_over_window(make_test_opts(), delivered);
    CHECK(delivered == 101);
    REQUIRE(count == 0);
}

TEST_CASE("steady-state authenticated-only receive-deliver allocates nothing", "[encrypted_socket][alloc]")
{
    auto opts = make_test_opts();
    opts.encrypt.auth_only = true;
    uint64_t delivered = 0;
    const uint64_t count = allocations_over_window(opts, delivered);
    CHECK(delivered == 101);
    REQUIRE(count == 0);
}
