#ifndef HPP_GUARD_MDNSPP_DISCOVERY_FIXTURE_H
#define HPP_GUARD_MDNSPP_DISCOVERY_FIXTURE_H

#include "helpers.h"

#include "mdnspp/service_type.h"
#include "mdnspp/callback_types.h"

#include <catch2/catch_test_macros.hpp>

#include <vector>
#include <cstddef>
#include <utility>
#include <variant>
#include <string_view>
#include <system_error>

template <typename Result>
struct outcome
{
    outcome()
        : fired{false}
        , ec{}
        , results{}
    {
    }

    bool fired;
    std::error_code ec;
    std::vector<Result> results;
};

using discover_outcome = outcome<mdnspp::mdns_record_variant>;
using browse_outcome = outcome<mdnspp::resolved_service>;
using enumerate_outcome = outcome<mdnspp::service_type_info>;

template <typename Result>
mdnspp::move_only_function<void(std::error_code, std::vector<Result>)> record_into(outcome<Result> &out)
{
    return [&out](std::error_code ec, std::vector<Result> results)
    {
        out.fired = true;
        out.ec = ec;
        out.results = std::move(results);
    };
}

inline mdnspp::discovery_completion_handler ignore_discovery()
{
    return [](std::error_code, std::vector<mdnspp::mdns_record_variant>) {};
}

inline mdnspp::browse_completion_handler ignore_browse()
{
    return [](std::error_code, std::vector<mdnspp::resolved_service>) {};
}

template <typename Result>
void check_completed(const outcome<Result> &out)
{
    REQUIRE(out.fired);
    REQUIRE_FALSE(out.ec);
}

template <typename Result>
void check_completed_with(const outcome<Result> &out, std::errc expected)
{
    REQUIRE(out.fired);
    REQUIRE(out.ec == expected);
}

inline void check_single_ptr(const std::vector<mdnspp::mdns_record_variant> &results, std::string_view label)
{
    REQUIRE(results.size() == 1);
    REQUIRE(std::holds_alternative<mdnspp::record_ptr>(results[0]));
    REQUIRE(std::get<mdnspp::record_ptr>(results[0]).ptr_name.find(label) != mdnspp::dns_name::npos);
}

struct discovery_fixture
{
    discovery_fixture()
        : ex{}
        , found{}
        , browsed{}
        , sd{ex, mdnspp::query_options{.silence_timeout = 500ms}}
    {
    }

    void discover(mdnspp::discovery_completion_handler on_done = ignore_discovery(),
                  std::string_view service_type = "_http._tcp.local.")
    {
        sd.async_discover(service_type, std::move(on_done));
    }

    void browse(mdnspp::browse_completion_handler on_done = ignore_browse())
    {
        sd.async_browse("_http._tcp.local.", std::move(on_done));
    }

    void enqueue(std::vector<std::byte> packet)
    {
        sd.socket().enqueue(std::move(packet));
    }

    void stop()
    {
        sd.stop();
        ex.drain_posted();
    }

    void fire_silence()
    {
        sd.timer().fire();
    }

    // The RFC 6762 section 5.2 delay before the first query.
    void fire_delay()
    {
        sd.delay_timer().fire();
    }

    mock_executor ex;
    discover_outcome found;
    browse_outcome browsed;
    mdnspp::basic_service_discovery<mock_policy> sd;
};

inline void check_sent_to_multicast(discovery_fixture &f)
{
    REQUIRE_FALSE(f.sd.socket().sent_packets().empty());
    REQUIRE(f.sd.socket().sent_packets()[0].dest == mdnspp::endpoint{"224.0.0.251", 5353});
}

#endif
