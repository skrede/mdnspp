#include "mdnspp/detail/socket_registry.h"

#include <catch2/catch_test_macros.hpp>

#include <span>
#include <vector>
#include <cstddef>
#include <system_error>

using mdnspp::detail::native_socket_t;
using mdnspp::detail::receive_handler;
using mdnspp::detail::socket_registry;

namespace {

constexpr native_socket_t fd_a = 3;
constexpr native_socket_t fd_b = 4;
constexpr native_socket_t fd_c = 5;

std::vector<native_socket_t> polled(const socket_registry &registry)
{
    std::vector<pollfd> fds;
    registry.build_pollfds(fds);
    std::vector<native_socket_t> out;
    for(const pollfd &p : fds)
        out.push_back(p.fd);
    return out;
}

receive_handler noop()
{
    return [](std::error_code, const mdnspp::recv_metadata &, std::span<std::byte>) {};
}

void invoke(receive_handler &handler)
{
    handler(std::error_code{}, mdnspp::recv_metadata{}, std::span<std::byte>{});
}

socket_registry three_sockets()
{
    socket_registry registry;
    registry.add(fd_a);
    registry.add(fd_b);
    registry.add(fd_c);
    return registry;
}

}

TEST_CASE("only armed sockets are polled", "[socket_registry]")
{
    socket_registry registry = three_sockets();
    registry.arm(fd_a, noop());
    registry.arm(fd_c, noop());
    REQUIRE(polled(registry) == std::vector<native_socket_t>{fd_a, fd_c});
    REQUIRE(registry.contains(fd_b));
    REQUIRE_FALSE(registry.armed(fd_b));
}

TEST_CASE("taking a handler disarms its socket", "[socket_registry]")
{
    socket_registry registry = three_sockets();
    registry.arm(fd_a, noop());
    registry.arm(fd_b, noop());
    receive_handler taken = registry.take_handler(fd_a);
    REQUIRE(taken);
    REQUIRE_FALSE(registry.armed(fd_a));
    REQUIRE(polled(registry) == std::vector<native_socket_t>{fd_b});
    REQUIRE_FALSE(registry.take_handler(fd_a));
}

TEST_CASE("removing a socket inside its own handler leaves the others armed", "[socket_registry]")
{
    socket_registry registry = three_sockets();
    for(const native_socket_t fd : {fd_a, fd_b, fd_c})
        registry.arm(fd, noop());
    receive_handler taken = registry.take_handler(fd_b);
    registry.remove(fd_b);
    invoke(taken);
    REQUIRE_FALSE(registry.contains(fd_b));
    REQUIRE(polled(registry) == std::vector<native_socket_t>{fd_a, fd_c});
}

TEST_CASE("re-arming inside the invoked handler polls the socket again", "[socket_registry]")
{
    socket_registry registry = three_sockets();
    registry.arm(fd_a, noop());
    receive_handler taken = registry.take_handler(fd_a);
    REQUIRE(polled(registry).empty());
    registry.arm(fd_a, noop());
    invoke(taken);
    REQUIRE(polled(registry) == std::vector<native_socket_t>{fd_a});
}

TEST_CASE("arming an unknown or removed socket drops the handler", "[socket_registry]")
{
    socket_registry registry = three_sockets();
    registry.arm(fd_a, noop());
    registry.remove(fd_a);
    registry.arm(fd_a, noop());
    registry.arm(native_socket_t{42}, noop());
    REQUIRE_FALSE(registry.armed(fd_a));
    REQUIRE_FALSE(registry.contains(native_socket_t{42}));
    REQUIRE(polled(registry).empty());
}

TEST_CASE("adding a known socket again keeps its armed handler", "[socket_registry]")
{
    socket_registry registry;
    registry.add(fd_a);
    registry.arm(fd_a, noop());
    registry.add(fd_a);
    REQUIRE(registry.armed(fd_a));
    REQUIRE(polled(registry) == std::vector<native_socket_t>{fd_a});
}
