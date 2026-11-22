#include "helpers.h"

#include "support/skip_or_fail.h"
#include "support/alloc_counter.h"

#include "mdnspp/socket_options.h"

#include "mdnspp/detail/native_socket.h"

#include "mdnspp/default/default_timer.h"
#include "mdnspp/default/default_socket.h"
#include "mdnspp/default/default_context.h"

#include <catch2/catch_test_macros.hpp>

#include <span>
#include <string>
#include <cstddef>
#include <cstdint>
#include <string_view>
#include <system_error>

namespace {

using backend_socket = mdnspp::encrypt::encrypted_socket<mdnspp::default_socket>;

uint16_t bound_port(mdnspp::detail::native_socket_t fd)
{
    sockaddr_storage addr{};
    socklen_t len = sizeof(addr);
    ::getsockname(fd, reinterpret_cast<sockaddr *>(&addr), &len);
    if(addr.ss_family == AF_INET6)
        return ntohs(reinterpret_cast<const sockaddr_in6 &>(addr).sin6_port);
    return ntohs(reinterpret_cast<const sockaddr_in &>(addr).sin_port);
}

mdnspp::encrypt::encrypt_socket_options loopback_opts(const char *group, const char *loopback, uint32_t sender_id)
{
    auto opts = make_test_opts(std::byte{0x42}, sender_id);
    opts.multicast_group = mdnspp::endpoint{group, 0};
    // Darwin rejects an IPv6 link-local group join with interface index 0 when it has no IPv6 route to the group.
    if(std::string_view{group}.find(':') != std::string_view::npos)
        opts.interface_address = loopback;
    return opts;
}

struct default_rig
{
    mdnspp::default_context ctx;
    std::error_code receiver_ec;
    std::error_code sender_ec;
    backend_socket receiver;
    backend_socket sender;
    mdnspp::endpoint dest;
    uint64_t delivered;

    default_rig(const char *group, const char *loopback)
        : ctx{}
        , receiver_ec{}
        , sender_ec{}
        , receiver(ctx, loopback_opts(group, loopback, 2), receiver_ec)
        , sender(ctx, loopback_opts(group, loopback, 1), sender_ec)
        , dest{loopback, receiver_ec ? uint16_t{0} : bound_port(receiver.inner().native_handle())}
        , delivered(0)
    {
        if(const std::error_code ec = receiver_ec ? receiver_ec : sender_ec)
            mdnspp::test_support::skip_or_fail("default_socket construction failed: " + ec.message());
        arm();
    }

    void arm()
    {
        receiver.async_receive([this](std::error_code, const mdnspp::recv_metadata &, std::span<std::byte>)
        {
            ++delivered;
            arm();
        });
    }

    void cycle(std::span<const std::byte> plaintext)
    {
        sender.send(dest, plaintext);
        ctx.poll_one();
    }
};

void require_silent_window(const char *group, const char *loopback)
{
    default_rig rig(group, loopback);
    const plain_bytes plaintext(200, std::byte{0x5A});
    rig.cycle(plaintext);
    mdnspp::test_support::reset_allocation_count();
    for(int i = 0; i < 50; ++i)
        rig.cycle(plaintext);
    const uint64_t count = mdnspp::test_support::allocation_count();
    CHECK(rig.delivered == 51);
    REQUIRE(count == 0);
}

}

TEST_CASE("steady-state encrypted send and deliver over the default socket allocates nothing",
          "[encrypted_socket][alloc][default_socket]")
{
    require_silent_window("224.0.0.251", "127.0.0.1");
}

TEST_CASE("steady-state encrypted send and deliver over the default socket on IPv6 loopback allocates nothing",
          "[encrypted_socket][alloc][default_socket]")
{
    require_silent_window("ff02::fb", "::1");
}
