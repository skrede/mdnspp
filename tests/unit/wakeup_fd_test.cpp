#include "mdnspp/detail/wakeup_fd.h"

#include "support/fd_limit.h"

#include <catch2/catch_test_macros.hpp>

#include <poll.h>
#include <fcntl.h>

#include <system_error>

using mdnspp::detail::wakeup_fd;
using mdnspp::detail::invalid_socket;
using mdnspp::detail::native_socket_t;
using mdnspp::test_support::fd_limit_guard;
using mdnspp::test_support::skip_unless_lowered;

namespace {

bool readable(native_socket_t fd)
{
    pollfd entry{fd, POLLIN, 0};
    return ::poll(&entry, 1, 0) == 1 && (entry.revents & POLLIN) != 0;
}

}

TEST_CASE("wakeup descriptor is close-on-exec", "[wakeup_fd]")
{
    wakeup_fd wakeup;
    wakeup.create();

    const int flags = ::fcntl(wakeup.native(), F_GETFD);
    REQUIRE(flags >= 0);
    REQUIRE((flags & FD_CLOEXEC) != 0);
}

TEST_CASE("creating the wakeup again releases the previous descriptors", "[wakeup_fd]")
{
    wakeup_fd wakeup;
    wakeup.create();
    const native_socket_t first = wakeup.native();

    wakeup.create();

    REQUIRE(wakeup.native() == first);
}

TEST_CASE("a recreated wakeup still signals readiness", "[wakeup_fd]")
{
    wakeup_fd wakeup;
    wakeup.create();
    wakeup.create();
    REQUIRE_FALSE(readable(wakeup.native()));

    wakeup.notify();
    REQUIRE(readable(wakeup.native()));

    wakeup.drain();
    REQUIRE_FALSE(readable(wakeup.native()));
}

TEST_CASE("creating the wakeup under descriptor exhaustion reports the error and leaves no descriptor", "[wakeup_fd]")
{
    wakeup_fd wakeup;
    std::error_code ec;
    {
        const fd_limit_guard guard{1};
        skip_unless_lowered(guard);
        wakeup.create(ec);
    }
    REQUIRE(ec == std::errc::too_many_files_open);
    REQUIRE(wakeup.native() == invalid_socket);

    wakeup.create(ec);
    REQUIRE_FALSE(ec);
    REQUIRE(wakeup.native() != invalid_socket);
}
