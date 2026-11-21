#ifndef HPP_GUARD_MDNSPP_ASIO_TOKEN_HELPERS_H
#define HPP_GUARD_MDNSPP_ASIO_TOKEN_HELPERS_H

#include "support/sync_wait.h"
#include "support/construct_or_skip.h"

#include "mdnspp/asio.h"
#include "mdnspp/service_info.h"

#include "mdnspp/detail/dns_enums.h"

#include <asio.hpp>
#include <asio/as_tuple.hpp>
#include <asio/deferred.hpp>
#include <asio/detached.hpp>
#include <asio/use_future.hpp>
#include <asio/cancel_after.hpp>
#include <asio/use_awaitable.hpp>

#ifdef ASIO_HAS_CO_AWAIT
#include <asio/co_spawn.hpp>
#include <asio/experimental/awaitable_operators.hpp>
#endif

#include <catch2/catch_test_macros.hpp>

#include <atomic>
#include <chrono>
#include <future>
#include <memory>
#include <string>
#include <thread>
#include <optional>

using namespace std::chrono_literals;
using mdnspp::test_support::construct_or_skip;

inline mdnspp::service_info make_info(const std::string &name, const std::string &host, uint16_t port,
                                      const std::string &ipv4)
{
    mdnspp::service_info info;
    info.service_name = name + "._http._tcp.local.";
    info.service_type = "_http._tcp.local.";
    info.hostname = host + ".local.";
    info.port = port;
    info.address_ipv4 = ipv4;
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

inline mdnspp::query_options silent_for(std::chrono::milliseconds silence)
{
    return mdnspp::query_options{.silence_timeout = silence};
}

struct completion_probe
{
    std::atomic<int32_t> count;
    std::error_code ec;

    explicit completion_probe(std::error_code initial = {})
        : count{0}, ec{initial}
    {
    }

    bool fired() const { return count.load() > 0; }

    auto handler()
    {
        return [this](std::error_code result)
        {
            ec = result;
            count.fetch_add(1);
        };
    }
};

template <typename Subject>
struct io_subject_fixture
{
    asio::io_context io;
    std::optional<Subject> subject;

    io_subject_fixture()
        : io{}, subject{}
    {
    }

    template <typename... Args>
    void create(Args &&...args)
    {
        construct_or_skip("asio_policy object", [&] { subject.emplace(io, std::forward<Args>(args)...); });
    }
};

using discovery_fixture = io_subject_fixture<mdnspp::basic_service_discovery<mdnspp::asio_policy>>;
using querier_fixture = io_subject_fixture<mdnspp::basic_querier<mdnspp::asio_policy>>;

struct observer_fixture
{
    asio::io_context io;
    std::shared_ptr<mdnspp::basic_observer<mdnspp::asio_policy>> obs;

    observer_fixture()
        : io{}, obs{}
    {
        construct_or_skip("observer<asio_policy>", [&]
        {
            obs = std::make_shared<mdnspp::basic_observer<mdnspp::asio_policy>>(
                io, mdnspp::observer_options{
                    .on_record = [](const mdnspp::endpoint &, const mdnspp::mdns_record_variant &) {}});
        });
    }

    void run_then_stop()
    {
        std::thread io_thread([this] { io.run(); });
        const bool synced = mdnspp::test_support::round_trip([this](auto marker) { asio::post(io, std::move(marker)); },
                                                             5s);
        obs->stop();
        io_thread.join();
        obs.reset();
        REQUIRE(synced);
    }
};

struct server_fixture
{
    asio::io_context io;
    std::shared_ptr<mdnspp::basic_service_server<mdnspp::asio_policy>> server;
    std::thread io_thread;

    server_fixture()
        : io{}, server{}, io_thread{}
    {
    }

    ~server_fixture()
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
        construct_or_skip("service_server<asio_policy>", [&]
        {
            server = std::make_shared<mdnspp::basic_service_server<mdnspp::asio_policy>>(
                io, std::forward<Args>(args)...);
        });
    }

    void run_io()
    {
        io_thread = std::thread([this] { io.run(); });
    }

    void sync_io()
    {
        REQUIRE(mdnspp::test_support::round_trip([this](auto marker) { asio::post(io, std::move(marker)); }, 5s));
    }

    void stop_and_join()
    {
        server->stop();
        io_thread.join();
        server.reset();
    }
};

#endif
