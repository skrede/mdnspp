#ifndef HPP_GUARD_MDNSPP_RECV_LOOP_HELPERS_H
#define HPP_GUARD_MDNSPP_RECV_LOOP_HELPERS_H

#include "mdnspp/detail/recv_loop.h"

#include "mdnspp/testing/mock_policy.h"

#include <catch2/catch_test_macros.hpp>

#include <span>
#include <chrono>
#include <vector>
#include <cstddef>
#include <system_error>

namespace mdnspp::test_support {

inline constexpr std::chrono::milliseconds SILENCE_TIMEOUT{500};

inline std::vector<std::byte> make_packet(std::size_t n)
{
    std::vector<std::byte> v(n);
    for(std::size_t i = 0; i < n; ++i)
        v[i] = static_cast<std::byte>(i % 256);
    return v;
}

struct loop_rig
{
    testing::mock_executor ex;
    testing::mock_socket sock;
    testing::mock_timer timer;
    std::vector<std::vector<std::byte>> packets;
    std::vector<std::error_code> errors;
    int silences;
    detail::recv_loop<testing::mock_policy> loop;

    loop_rig()
        : ex{}
        , sock{ex}
        , timer{ex}
        , packets{}
        , errors{}
        , silences{0}
        , loop{sock, timer, SILENCE_TIMEOUT, [this](const recv_metadata &, std::span<std::byte> data) -> bool
            {
                packets.emplace_back(data.begin(), data.end());
                return true;
            },
            [this] { ++silences; }, [this](std::error_code ec) { errors.push_back(ec); }}
    {
    }
};

inline void expect_armed(loop_rig &rig)
{
    REQUIRE(rig.sock.has_pending_receive());
}

inline void expect_backoff(loop_rig &rig, std::chrono::milliseconds delay)
{
    REQUIRE_FALSE(rig.sock.has_pending_receive());
    REQUIRE(rig.timer.last_duration() == delay);
}

inline void fail_transiently(loop_rig &rig, std::errc code)
{
    rig.sock.inject_error(std::make_error_code(code));
}

}

#endif
