#ifndef HPP_GUARD_MDNSPP_QUERIER_FIXTURE_H
#define HPP_GUARD_MDNSPP_QUERIER_FIXTURE_H

#include "helpers.h"

#include "mdnspp/callback_types.h"

#include <catch2/catch_test_macros.hpp>

#include <vector>
#include <cstddef>
#include <utility>
#include <variant>
#include <string_view>
#include <system_error>

struct query_outcome
{
    query_outcome()
        : fired{false}
        , ec{}
        , results{}
    {
    }

    bool fired;
    std::error_code ec;
    std::vector<mdnspp::mdns_record_variant> results;
};

inline mdnspp::querier_completion_handler ignore_completion()
{
    return [](std::error_code, std::vector<mdnspp::mdns_record_variant>) {};
}

inline mdnspp::querier_completion_handler record_into(query_outcome &out)
{
    return [&out](std::error_code ec, std::vector<mdnspp::mdns_record_variant> results)
    {
        out.fired = true;
        out.ec = ec;
        out.results = std::move(results);
    };
}

inline void check_single_a(const std::vector<mdnspp::mdns_record_variant> &results, std::string_view address)
{
    REQUIRE(results.size() == 1);
    REQUIRE(std::holds_alternative<mdnspp::record_a>(results[0]));
    REQUIRE(std::get<mdnspp::record_a>(results[0]).address_string == address);
}

struct querier_fixture
{
    querier_fixture()
        : ex{}
        , done{}
        , q{ex, mdnspp::query_options{.silence_timeout = 500ms}}
    {
    }

    void query(mdnspp::querier_completion_handler on_done = ignore_completion(),
               std::string_view name = "myhost.local.", mdnspp::response_mode mode = mdnspp::response_mode::multicast)
    {
        q.async_query(name, mdnspp::dns_type::a, std::move(on_done), mode);
    }

    void enqueue(std::vector<std::byte> packet)
    {
        q.socket().enqueue(std::move(packet));
    }

    void inject(std::vector<std::byte> packet)
    {
        q.socket().inject_receive(mdnspp::endpoint{}, std::move(packet));
    }

    void fire_silence()
    {
        q.timer().fire();
    }

    void fire_delay()
    {
        q.delay_timer().fire();
    }

    mock_executor ex;
    query_outcome done;
    mdnspp::basic_querier<mock_policy> q;
};

#endif
