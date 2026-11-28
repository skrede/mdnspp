#include "helpers.h"

TEST_CASE_METHOD(discovery_fixture, "async_discover with use_future returns future with results",
                 "[completion_token][use_future][service_discovery]")
{
    create(silent_for(500ms));

    auto fut = mdnspp::async_discover(*subject, "_nonexistent._tcp.local.", asio::use_future);
    io.run();

    auto results = fut.get();
    REQUIRE(results.empty());
}

TEST_CASE_METHOD(discovery_fixture, "async_browse with use_future returns future with services",
                 "[completion_token][use_future][service_discovery][browse]")
{
    create(silent_for(500ms));

    auto fut = mdnspp::async_browse(*subject, "_nonexistent._tcp.local.", asio::use_future);
    io.run();

    auto services = fut.get();
    REQUIRE(services.empty());
}

TEST_CASE_METHOD(querier_fixture, "async_query with use_future returns future with results",
                 "[completion_token][use_future][querier]")
{
    create(silent_for(500ms));

    auto fut = mdnspp::async_query(*subject, "_nonexistent._tcp.local.", mdnspp::dns_type::ptr, asio::use_future);
    io.run();

    auto results = fut.get();
    REQUIRE(results.empty());
}

TEST_CASE_METHOD(discovery_fixture, "async_discover with deferred does not initiate I/O until launched",
                 "[completion_token][deferred][service_discovery]")
{
    create(silent_for(300ms));

    auto op = mdnspp::async_discover(*subject, "_deferred._tcp.local.", asio::deferred);

    bool callback_fired = false;
    std::move(op)([&callback_fired](std::error_code, std::vector<mdnspp::mdns_record_variant>)
    {
        callback_fired = true;
    });

    io.run();
    REQUIRE(callback_fired);
}

TEST_CASE_METHOD(discovery_fixture, "async_browse with deferred does not initiate I/O until launched",
                 "[completion_token][deferred][service_discovery][browse]")
{
    create(silent_for(300ms));

    auto op = mdnspp::async_browse(*subject, "_deferred._tcp.local.", asio::deferred);

    bool callback_fired = false;
    std::move(op)([&callback_fired](std::error_code, std::vector<mdnspp::resolved_service>)
    {
        callback_fired = true;
    });

    io.run();
    REQUIRE(callback_fired);
}

#ifdef ASIO_HAS_CO_AWAIT

TEST_CASE_METHOD(discovery_fixture, "async_browse with use_awaitable returns services when complete",
                 "[completion_token][use_awaitable][service_discovery][browse]")
{
    create(silent_for(300ms));

    bool completed = false;
    asio::co_spawn(
        io,
        [this, &completed]() -> asio::awaitable<void>
        {
            auto services = co_await mdnspp::async_browse(*subject, "_nonexistent._tcp.local.", asio::use_awaitable);
            REQUIRE(services.empty());
            completed = true;
        },
        asio::detached);

    io.run();
    REQUIRE(completed);
}

#endif
