#include "mdnspp/detail/recv_loop.h"

#include "mdnspp/testing/mock_policy.h"

#include <catch2/catch_test_macros.hpp>

#include <span>
#include <chrono>
#include <vector>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <system_error>

using namespace mdnspp;
using namespace mdnspp::testing;

static constexpr std::chrono::milliseconds SILENCE_TIMEOUT{500};

// Helper: build a packet of N bytes (value = i % 256)
static std::vector<std::byte> make_packet(std::size_t n)
{
    std::vector<std::byte> v(n);
    for(std::size_t i = 0; i < n; ++i)
        v[i] = static_cast<std::byte>(i % 256);
    return v;
}

TEST_CASE("recv_loop delivers injected packets")
{
    mock_executor ex;
    mock_socket sock{ex};
    mock_timer timer{ex};
    auto pkt = make_packet(8);
    sock.enqueue(pkt);

    std::vector<std::vector<std::byte>> received;
    detail::recv_loop<mock_policy> loop{
        sock,
        timer,
        SILENCE_TIMEOUT,
        [&](const recv_metadata &, std::span<std::byte> data) -> bool
        {
            received.emplace_back(data.begin(), data.end());
            return true;
        },
        []
        {
        }
    };

    loop.start();

    REQUIRE(received.size() == 1);
    REQUIRE(received[0] == pkt);
}

TEST_CASE("recv_loop silence callback fires on timer fire")
{
    mock_executor ex;
    mock_socket sock{ex};
    mock_timer timer{ex};

    bool silence_called = false;
    detail::recv_loop<mock_policy> loop{
        sock,
        timer,
        SILENCE_TIMEOUT,
        [](const recv_metadata &, std::span<std::byte>) -> bool { return true; },
        [&] { silence_called = true; }
    };

    loop.start();

    // Fire the pending timer handler — simulates silence timeout expiring
    timer.fire();

    REQUIRE(silence_called == true);
}

TEST_CASE("recv_loop stop is idempotent")
{
    mock_executor ex;
    mock_socket sock{ex};
    mock_timer timer{ex};

    detail::recv_loop<mock_policy> loop{
        sock,
        timer,
        SILENCE_TIMEOUT,
        [](const recv_metadata &, std::span<std::byte>) -> bool { return true; },
        []
        {
        }
    };

    loop.start();

    // Calling stop() twice must not crash or double-invoke cancel
    REQUIRE_NOTHROW(loop.stop());
    REQUIRE_NOTHROW(loop.stop());
}

TEST_CASE("recv_loop stop prevents on_packet after stop")
{
    mock_executor ex;
    mock_socket sock{ex};
    mock_timer timer{ex};

    // Enqueue a packet — but stop() before start()
    sock.enqueue(make_packet(4));

    int packet_calls = 0;
    detail::recv_loop<mock_policy> loop{
        sock,
        timer,
        SILENCE_TIMEOUT,
        [&](const recv_metadata &, std::span<std::byte>) -> bool
        {
            ++packet_calls;
            return true;
        },
        []
        {
        }
    };

    loop.stop();
    loop.start(); // arm_receive() checks m_stopped first — should be a no-op

    REQUIRE(packet_calls == 0);
}

TEST_CASE("recv_loop resets silence timer on each packet")
{
    mock_executor ex;
    mock_socket sock{ex};
    mock_timer timer{ex};

    // Enqueue 2 packets — each delivery should call arm_silence_timer()
    sock.enqueue(make_packet(4));
    sock.enqueue(make_packet(4));

    detail::recv_loop<mock_policy> loop{
        sock,
        timer,
        SILENCE_TIMEOUT,
        [](const recv_metadata &, std::span<std::byte>) -> bool { return true; },
        []
        {
        }
    };

    loop.start();

    // start() calls arm_silence_timer() once, then:
    //   packet 1 triggers arm_silence_timer() (expires_after +1) + arm_receive()
    //   packet 2 triggers arm_silence_timer() (expires_after +1) + arm_receive() (no-op)
    // Minimum cancel_count >= 2 (at least 2 expires_after calls post-initial)
    REQUIRE(timer.cancel_count() >= 2);
}

TEST_CASE("recv_loop with ttl_unknown_policy::accept passes nullopt TTL packets")
{
    mock_executor ex;
    mock_socket sock{ex};
    mock_timer timer{ex};

    sock.enqueue(make_packet(8), endpoint{}, std::optional<uint8_t>{});

    int received = 0;
    detail::recv_loop<mock_policy> loop{
        sock,
        timer,
        SILENCE_TIMEOUT,
        [&](const recv_metadata &, std::span<std::byte>) -> bool
        {
            ++received;
            return true;
        },
        [](){},
        255,
        ttl_unknown_policy::accept
    };

    loop.start();

    REQUIRE(received == 1);
}

TEST_CASE("recv_loop with ttl_unknown_policy::reject drops nullopt TTL packets")
{
    mock_executor ex;
    mock_socket sock{ex};
    mock_timer timer{ex};

    sock.enqueue(make_packet(8), endpoint{}, std::optional<uint8_t>{});

    int received = 0;
    detail::recv_loop<mock_policy> loop{
        sock,
        timer,
        SILENCE_TIMEOUT,
        [&](const recv_metadata &, std::span<std::byte>) -> bool
        {
            ++received;
            return true;
        },
        [](){},
        255,
        ttl_unknown_policy::reject
    };

    loop.start();

    REQUIRE(received == 0);
}

TEST_CASE("recv_loop drops populated TTL below receive_ttl_minimum")
{
    mock_executor ex;
    mock_socket sock{ex};
    mock_timer timer{ex};

    // TTL=10, minimum=255 — should be dropped
    sock.enqueue(make_packet(8), endpoint{}, std::optional<uint8_t>{uint8_t{10}});

    int received = 0;
    detail::recv_loop<mock_policy> loop{
        sock,
        timer,
        SILENCE_TIMEOUT,
        [&](const recv_metadata &, std::span<std::byte>) -> bool
        {
            ++received;
            return true;
        },
        [](){},
        255,
        ttl_unknown_policy::accept
    };

    loop.start();

    REQUIRE(received == 0);
}

TEST_CASE("recv_loop passes populated TTL at or above receive_ttl_minimum")
{
    mock_executor ex;
    mock_socket sock{ex};
    mock_timer timer{ex};

    // TTL=255, minimum=255 — should pass
    sock.enqueue(make_packet(8), endpoint{}, std::optional<uint8_t>{uint8_t{255}});

    int received = 0;
    detail::recv_loop<mock_policy> loop{
        sock,
        timer,
        SILENCE_TIMEOUT,
        [&](const recv_metadata &, std::span<std::byte>) -> bool
        {
            ++received;
            return true;
        },
        [](){},
        255,
        ttl_unknown_policy::accept
    };

    loop.start();

    REQUIRE(received == 1);
}

TEST_CASE("recv_loop re-arms the receive after a transient error")
{
    mock_executor ex;
    mock_socket sock{ex};
    mock_timer timer{ex};

    int received = 0;
    std::vector<std::error_code> errors;
    detail::recv_loop<mock_policy> loop{
        sock,
        timer,
        SILENCE_TIMEOUT,
        [&](const recv_metadata &, std::span<std::byte>) -> bool
        {
            ++received;
            return true;
        },
        [](){},
        0,
        ttl_unknown_policy::accept,
        [&](std::error_code ec) { errors.push_back(ec); }
    };

    loop.start();
    REQUIRE(sock.has_pending_receive());

    sock.inject_error(std::make_error_code(std::errc::connection_reset));

    REQUIRE(errors.empty());
    REQUIRE(sock.has_pending_receive());

    sock.inject_receive(endpoint{}, make_packet(4));
    REQUIRE(received == 1);
}

TEST_CASE("recv_loop backs off on consecutive transient errors and resets on success")
{
    mock_executor ex;
    mock_socket sock{ex};
    mock_timer timer{ex};

    int received = 0;
    std::vector<std::error_code> errors;
    detail::recv_loop<mock_policy> loop{
        sock,
        timer,
        SILENCE_TIMEOUT,
        [&](const recv_metadata &, std::span<std::byte>) -> bool
        {
            ++received;
            return true;
        },
        [](){},
        0,
        ttl_unknown_policy::accept,
        [&](std::error_code ec) { errors.push_back(ec); }
    };

    loop.start();
    REQUIRE(sock.has_pending_receive());

    // First transient failure: immediate re-arm, no backoff wait.
    sock.inject_error(std::make_error_code(std::errc::not_enough_memory));
    REQUIRE(sock.has_pending_receive());
    REQUIRE(timer.last_duration() == SILENCE_TIMEOUT);

    // Second consecutive failure: re-arm deferred by the initial 10 ms backoff.
    sock.inject_error(std::make_error_code(std::errc::not_enough_memory));
    REQUIRE_FALSE(sock.has_pending_receive());
    REQUIRE(timer.last_duration() == std::chrono::milliseconds(10));

    // Backoff fires: silence wait restored (remaining window), receive re-armed.
    timer.fire();
    REQUIRE(sock.has_pending_receive());
    REQUIRE(timer.last_duration() <= SILENCE_TIMEOUT);

    // Third consecutive failure: backoff doubles to 20 ms.
    sock.inject_error(std::make_error_code(std::errc::no_buffer_space));
    REQUIRE_FALSE(sock.has_pending_receive());
    REQUIRE(timer.last_duration() == std::chrono::milliseconds(20));

    timer.fire();
    REQUIRE(sock.has_pending_receive());

    // A successful receive resets the backoff state.
    sock.inject_receive(endpoint{}, make_packet(4));
    REQUIRE(received == 1);
    REQUIRE(sock.has_pending_receive());

    // The next transient failure re-arms immediately again.
    sock.inject_error(std::make_error_code(std::errc::not_enough_memory));
    REQUIRE(sock.has_pending_receive());

    // No transient error was ever reported as fatal.
    REQUIRE(errors.empty());
}

TEST_CASE("recv_loop backoff caps at 500 ms under persistent transient failure")
{
    mock_executor ex;
    mock_socket sock{ex};
    mock_timer timer{ex};

    detail::recv_loop<mock_policy> loop{
        sock,
        timer,
        SILENCE_TIMEOUT,
        [](const recv_metadata &, std::span<std::byte>) -> bool { return true; },
        [](){}
    };

    loop.start();

    sock.inject_error(std::make_error_code(std::errc::no_buffer_space)); // immediate re-arm
    std::chrono::milliseconds last{0};
    for(int i = 0; i < 12; ++i)
    {
        sock.inject_error(std::make_error_code(std::errc::no_buffer_space));
        REQUIRE_FALSE(sock.has_pending_receive());
        last = timer.last_duration();
        REQUIRE(last <= std::chrono::milliseconds(500));
        timer.fire(); // backoff elapses, receive re-armed
        REQUIRE(sock.has_pending_receive());
    }
    REQUIRE(last == std::chrono::milliseconds(500));
}

TEST_CASE("recv_loop reports a fatal error and stops re-arming")
{
    mock_executor ex;
    mock_socket sock{ex};
    mock_timer timer{ex};

    int received = 0;
    std::vector<std::error_code> errors;
    detail::recv_loop<mock_policy> loop{
        sock,
        timer,
        SILENCE_TIMEOUT,
        [&](const recv_metadata &, std::span<std::byte>) -> bool
        {
            ++received;
            return true;
        },
        [](){},
        0,
        ttl_unknown_policy::accept,
        [&](std::error_code ec) { errors.push_back(ec); }
    };

    loop.start();
    REQUIRE(sock.has_pending_receive());

    sock.inject_error(std::make_error_code(std::errc::operation_canceled));

    REQUIRE(errors.size() == 1);
    REQUIRE(errors[0] == std::make_error_code(std::errc::operation_canceled));
    REQUIRE_FALSE(sock.has_pending_receive());
    REQUIRE(received == 0);
}
