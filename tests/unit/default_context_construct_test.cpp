#include "mdnspp/default/default_timer.h"

#include "support/fd_limit.h"

#include <catch2/catch_test_macros.hpp>

#include <optional>
#include <system_error>

using mdnspp::default_context;
using mdnspp::test_support::fd_limit_guard;
using mdnspp::test_support::skip_unless_lowered;

namespace {

std::error_code construct_under_fd_limit(std::optional<default_context> &ctx)
{
    const fd_limit_guard guard{1};
    skip_unless_lowered(guard);
    std::error_code ec;
    ctx.emplace(ec);
    return ec;
}

template <typename F>
std::error_code thrown_by(F &&fn)
{
    try
    {
        fn();
    }
    catch(const std::system_error &e)
    {
        return e.code();
    }
    return std::error_code{};
}

}

TEST_CASE("a context constructed under descriptor exhaustion reports the error without throwing", "[default_context]")
{
    std::optional<default_context> ctx;
    std::error_code ec;
    REQUIRE_NOTHROW(ec = construct_under_fd_limit(ctx));
    REQUIRE(ctx.has_value());
    REQUIRE(ec == std::errc::too_many_files_open);
}

TEST_CASE("a context whose construction failed reports bad_file_descriptor instead of waiting", "[default_context]")
{
    std::optional<default_context> ctx;
    REQUIRE(construct_under_fd_limit(ctx) == std::errc::too_many_files_open);
    std::error_code ran;
    ctx->run(ran);
    std::error_code polled;
    ctx->poll_one(polled);
    REQUIRE(ran == std::errc::bad_file_descriptor);
    REQUIRE(polled == std::errc::bad_file_descriptor);
    REQUIRE(thrown_by([&] { ctx->run(); }) == std::errc::bad_file_descriptor);
    REQUIRE(thrown_by([&] { ctx->poll_one(); }) == std::errc::bad_file_descriptor);
}

TEST_CASE("the default constructor throws a descriptor exhaustion as system_error", "[default_context]")
{
    std::error_code thrown;
    {
        const fd_limit_guard guard{1};
        skip_unless_lowered(guard);
        thrown = thrown_by([] { const default_context ctx; });
    }
    REQUIRE(thrown == std::errc::too_many_files_open);
}

TEST_CASE("a successful construction clears a stale error", "[default_context]")
{
    std::error_code ec = std::make_error_code(std::errc::io_error);
    default_context ctx(ec);
    REQUIRE_FALSE(ec);
    ctx.poll_one(ec);
    REQUIRE_FALSE(ec);
}
