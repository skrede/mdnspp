#include "mdnspp/mdns_options.h"

#include "mdnspp/detail/mdns_options_validation.h"

#include <catch2/catch_test_macros.hpp>

#include <chrono>
#include <vector>
#include <utility>
#include <system_error>

using mdnspp::mdns_options;
using mdnspp::detail::validate_mdns_options;

namespace {

template <typename T>
concept has_max_known_answers = requires(T opts) { opts.max_known_answers; };

template <typename T>
concept has_record_ttl = requires(T opts) { opts.record_ttl; };

std::error_code validate_thresholds(std::vector<double> thresholds)
{
    mdns_options opts;
    opts.ttl_refresh_thresholds = std::move(thresholds);
    return validate_mdns_options(opts);
}

}

TEST_CASE("validate_mdns_options accepts the defaults", "[mdns_options][validate]")
{
    CHECK_FALSE(validate_mdns_options(mdns_options{}));
}

TEST_CASE("validate_mdns_options accepts an empty and a single ttl refresh threshold", "[mdns_options][validate]")
{
    CHECK_FALSE(validate_thresholds({}));
    CHECK_FALSE(validate_thresholds({0.5}));
}

TEST_CASE("validate_mdns_options rejects decreasing ttl refresh thresholds", "[mdns_options][validate]")
{
    CHECK(validate_thresholds({0.9, 0.8}) == std::errc::invalid_argument);
}

TEST_CASE("validate_mdns_options rejects equal ttl refresh thresholds", "[mdns_options][validate]")
{
    CHECK(validate_thresholds({0.8, 0.8}) == std::errc::invalid_argument);
}

TEST_CASE("validate_mdns_options rejects a zero and a negative qu_response_window", "[mdns_options][validate]")
{
    CHECK(validate_mdns_options(mdns_options{.qu_response_window = std::chrono::milliseconds{0}})
          == std::errc::invalid_argument);
    CHECK(validate_mdns_options(mdns_options{.qu_response_window = std::chrono::milliseconds{-1}})
          == std::errc::invalid_argument);
    CHECK(mdns_options{}.qu_response_window == std::chrono::seconds{2});
}

TEST_CASE("mdns_options has no max_known_answers and no record_ttl", "[mdns_options]")
{
    STATIC_CHECK_FALSE(has_max_known_answers<mdns_options>);
    STATIC_CHECK_FALSE(has_record_ttl<mdns_options>);
}
