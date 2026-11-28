#ifndef HPP_GUARD_MDNSPP_ASIO_TSAN_HELPERS_H
#define HPP_GUARD_MDNSPP_ASIO_TSAN_HELPERS_H

#include "support/sync_wait.h"
#include "support/construct_or_skip.h"

#include "mdnspp/service_info.h"
#include "mdnspp/basic_service_server.h"

#include "mdnspp/asio/asio_policy.h"

#include <asio/post.hpp>

#include <catch2/catch_test_macros.hpp>

#include <atomic>
#include <chrono>
#include <string>
#include <thread>
#include <cstdint>
#include <optional>
#include <string_view>
#include <system_error>

using namespace std::chrono_literals;
using mdnspp::test_support::construct_or_skip;

// Each test binary passes its own instance name: ctest runs them concurrently on the shared
// mDNS port, and a common name would let one binary's records conflict with another's probes.
inline mdnspp::service_info make_tsan_info(std::string_view instance)
{
    mdnspp::service_info info;
    info.service_name = std::string(instance) + "._http._tcp.local.";
    info.service_type = "_http._tcp.local.";
    info.hostname = std::string(instance) + "-host.local.";
    info.port = 8080;
    info.address_ipv4 = "192.168.1.10";
    return info;
}

inline mdnspp::service_options fast_service_options()
{
    return mdnspp::service_options{
        .announce_count = 1,
        .announce_interval = 10ms,
        .probe_count = 1,
        .probe_interval = 10ms,
        .probe_initial_delay_max = 0ms
    };
}

struct completion_log
{
    int32_t calls;
    std::error_code ec;

    void record(std::error_code received)
    {
        ++calls;
        ec = received;
    }
};

// A ThreadSanitizer build fails the run on any data race; the completion logs are what a case checks in every build.
// They are declared before the server, whose destructor completes still-pending handlers into them.
struct tsan_fixture
{
    asio::io_context io;
    completion_log ready;
    completion_log done;
    std::optional<mdnspp::basic_service_server<mdnspp::asio_policy>> server;
    std::thread io_thread;

    tsan_fixture()
        : io{}
        , ready{}
        , done{}
        , server{}
        , io_thread{}
    {
    }

    ~tsan_fixture()
    {
        if(io_thread.joinable())
        {
            io.stop();
            io_thread.join();
        }
    }

    template <typename... Args>
    void create(Args &&...args)
    {
        construct_or_skip("service_server<asio_policy>", [&] { server.emplace(io, std::forward<Args>(args)...); });
    }

    void run_io()
    {
        io_thread = std::thread([this] { io.run(); });
    }

    void start_logged()
    {
        server->async_start([this](std::error_code ec) { ready.record(ec); },
                            [this](std::error_code ec) { done.record(ec); });
        run_io();
    }

    void sync_io()
    {
        REQUIRE(mdnspp::test_support::round_trip([this](auto marker) { asio::post(io, std::move(marker)); }, 5s));
    }

    void start_and_wait_live()
    {
        std::atomic<bool> live{false};
        server->async_start([&live](std::error_code) { live.store(true); });
        run_io();

        for(int32_t i = 0; i < 400 && !live.load(); ++i)
            std::this_thread::sleep_for(5ms);
        REQUIRE(live.load());
    }

    void join_and_reset()
    {
        io_thread.join();
        server.reset();
    }
};

#endif
