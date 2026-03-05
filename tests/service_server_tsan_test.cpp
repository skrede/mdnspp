// tests/service_server_tsan_test.cpp
// ThreadSanitizer hard-gate test for service_server<AsioPolicy>.

#include "mdnspp/service_server.h"
#include "mdnspp/service_info.h"

#include "mdnspp/asio/asio_policy.h"

#include <catch2/catch_test_macros.hpp>

#include <chrono>
#include <thread>

static mdnspp::service_info make_test_info()
{
    mdnspp::service_info info;
    info.service_name = "TSanTest._http._tcp.local.";
    info.service_type = "_http._tcp.local.";
    info.hostname = "tsanhost.local.";
    info.port = 8080;
    info.address_ipv4 = "192.168.1.10";
    return info;
}

SCENARIO("service_server stop() from separate thread is data-race-free", "[service_server][tsan][asio]")
{
    GIVEN("an asio::io_context and service_server<AsioPolicy>")
    {
        asio::io_context io;

        // AsioSocket construction joins a multicast group — may fail in sandboxed CI
        // with no network interface. Warn and skip gracefully.
        std::optional<mdnspp::service_server<mdnspp::AsioPolicy>> server;

        try
        {
            server.emplace(io, make_test_info());
        }
        catch(const std::exception &e)
        {
            WARN("Skipping TSan test — socket construction failed (no network): " << e.what());
            return;
        }

        WHEN("async_start() is called and the io_context runs on a background thread")
        {
            server->async_start();
            std::thread io_thread([&io] { io.run(); });

            AND_WHEN("stop() is called from the main thread after a brief pause")
            {
                std::this_thread::sleep_for(std::chrono::milliseconds(50));
                server->stop();

                THEN("the io_context thread joins cleanly with no crash or hang")
                {
                    io_thread.join();
                    // Reaching here without TSan error = pass.
                    // When compiled with -fsanitize=thread, any data race in stop()
                    // causes a non-zero exit and test failure before this line.
                    REQUIRE(true);
                }
            }
        }
    }
}

SCENARIO("service_server double stop is safe under concurrency", "[service_server][tsan][asio]")
{
    GIVEN("an asio::io_context and a started service_server<AsioPolicy>")
    {
        asio::io_context io;

        std::optional<mdnspp::service_server<mdnspp::AsioPolicy>> server;

        try
        {
            server.emplace(io, make_test_info());
        }
        catch(const std::exception &e)
        {
            WARN("Skipping TSan test — socket construction failed (no network): " << e.what());
            return;
        }

        server->async_start();
        std::thread io_thread([&io] { io.run(); });
        std::this_thread::sleep_for(std::chrono::milliseconds(50));

        WHEN("stop() is called concurrently from both main thread and a second thread")
        {
            std::thread stop_thread([&server] { server->stop(); });
            server->stop(); // concurrent stop from main thread

            THEN("both threads join cleanly and no TSan race is reported")
            {
                stop_thread.join();
                io_thread.join();
                // Double-stop under concurrency without TSan race = pass.
                // The atomic<bool> m_stopped flag must protect all shared state.
                REQUIRE(true);
            }
        }
    }
}
