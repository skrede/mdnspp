#include "helpers.h"

#include <catch2/catch_test_macros.hpp>

#include <chrono>
#include <system_error>

using namespace std::chrono_literals;

namespace {

service_options with_authority_ttl(std::chrono::seconds authority_ttl)
{
    return service_options{.probe_authority_ttl = authority_ttl};
}

std::error_code thrown_error(const mdns_options &mopts, std::chrono::seconds authority_ttl)
{
    mock_executor ex;
    try
    {
        basic_service_server<mock_policy> server{ex, make_test_info(), with_authority_ttl(authority_ttl), {}, mopts};
    }
    catch(const std::system_error &e)
    {
        return e.code();
    }
    return {};
}

std::error_code reported_error(const mdns_options &mopts, std::chrono::seconds authority_ttl)
{
    mock_executor ex;
    std::error_code ec;
    basic_service_server<mock_policy> server{ex, make_test_info(), with_authority_ttl(authority_ttl), {}, mopts, ec};
    return ec;
}

void check_rejected(const mdns_options &mopts, std::chrono::seconds authority_ttl = 120s)
{
    CHECK(thrown_error(mopts, authority_ttl) == std::errc::invalid_argument);
    CHECK(reported_error(mopts, authority_ttl) == std::errc::invalid_argument);
}

}

TEST_CASE("service_server accepts the default options through both constructors", "[service_server][validation]")
{
    CHECK_FALSE(thrown_error({}, 120s));
    CHECK_FALSE(reported_error({}, 120s));
}

TEST_CASE("service_server rejects a zero initial_interval", "[service_server][validation]")
{
    check_rejected(mdns_options{.initial_interval = 0ms});
}

TEST_CASE("service_server rejects a negative refresh_jitter_pct", "[service_server][validation]")
{
    check_rejected(mdns_options{.refresh_jitter_pct = -0.1});
}

TEST_CASE("service_server rejects decreasing ttl refresh thresholds", "[service_server][validation]")
{
    check_rejected(mdns_options{.ttl_refresh_thresholds = {0.9, 0.8}});
}

TEST_CASE("service_server rejects a zero probe_authority_ttl", "[service_server][validation]")
{
    check_rejected({}, 0s);
}

TEST_CASE("service_server rejects a negative probe_authority_ttl", "[service_server][validation]")
{
    check_rejected({}, -1s);
}
