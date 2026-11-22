#include "mdnspp/inproc/inproc_bus.h"
#include "mdnspp/inproc/inproc_socket.h"
#include "mdnspp/inproc/inproc_executor.h"

#include "mdnspp/policy.h"
#include "mdnspp/socket_options.h"

#include "mdnspp/testing/test_clock.h"

#include <catch2/catch_test_macros.hpp>

#include <span>
#include <array>
#include <memory>
#include <vector>
#include <cstddef>
#include <cstdint>
#include <utility>
#include <functional>
#include <system_error>

using mdnspp::inproc::inproc_bus;
using mdnspp::inproc::inproc_socket;
using mdnspp::inproc::inproc_executor;
using mdnspp::testing::test_clock;

namespace {

using group_socket = inproc_socket<test_clock>;

constexpr std::size_t group_size = 3;
constexpr std::size_t opened_count = 8;

void arm(group_socket &sock, uint32_t &count, std::function<void()> &reaction)
{
    sock.async_receive([&sock, &count, &reaction](std::error_code, const mdnspp::recv_metadata &, std::span<std::byte>)
    {
        ++count;
        if(reaction)
            std::exchange(reaction, nullptr)();
        arm(sock, count, reaction);
    });
}

struct group_fixture
{
    group_fixture()
        : bus()
        , ex(bus)
        , counts{}
        , reactions()
        , sockets()
        , sender(ex)
    {
        for(std::size_t i = 0; i < group_size; ++i)
        {
            sockets.push_back(std::make_unique<group_socket>(ex));
            arm(*sockets[i], counts[i], reactions[i]);
        }
    }

    void send_and_drain()
    {
        const std::byte payload[] = {std::byte{0x01}, std::byte{0x02}};
        sender.send(mdnspp::socket_options{}.multicast_group, std::span<const std::byte>{payload});
        ex.drain();
    }

    inproc_bus<test_clock> bus;
    inproc_executor<test_clock> ex;
    std::array<uint32_t, group_size> counts;
    std::array<std::function<void()>, group_size> reactions;
    std::vector<std::unique_ptr<group_socket>> sockets;
    group_socket sender;
};

}

TEST_CASE("a handler that opens sockets during a multicast delivery", "[inproc][bus][reentrancy]")
{
    group_fixture f;
    std::array<uint32_t, opened_count> opened_counts{};
    std::array<std::function<void()>, opened_count> opened_reactions;
    std::vector<std::unique_ptr<group_socket>> opened;
    f.reactions[0] = [&]
    {
        for(std::size_t i = 0; i < opened_count; ++i)
        {
            opened.push_back(std::make_unique<group_socket>(f.ex));
            arm(*opened.back(), opened_counts[i], opened_reactions[i]);
        }
    };

    f.send_and_drain();
    REQUIRE(opened.size() == opened_count);
    CHECK(f.counts == std::array<uint32_t, group_size>{1, 1, 1});
    CHECK(opened_counts == std::array<uint32_t, opened_count>{});

    f.send_and_drain();
    CHECK(f.counts == std::array<uint32_t, group_size>{2, 2, 2});
    CHECK(opened_counts == std::array<uint32_t, opened_count>{1, 1, 1, 1, 1, 1, 1, 1});
}

TEST_CASE("a handler that destroys another socket during a multicast delivery", "[inproc][bus][reentrancy]")
{
    group_fixture f;
    f.reactions[0] = [&f] { f.sockets[2].reset(); };

    f.send_and_drain();
    CHECK(f.counts == std::array<uint32_t, group_size>{1, 1, 0});
}

TEST_CASE("a handler that closes its own socket during a multicast delivery", "[inproc][bus][reentrancy]")
{
    group_fixture f;
    f.reactions[0] = [&f] { f.sockets[0]->close(); };

    f.send_and_drain();
    CHECK(f.counts == std::array<uint32_t, group_size>{1, 1, 1});
}
