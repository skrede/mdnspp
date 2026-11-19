#include "mdnspp/detail/wakeup_fd.h"

#include <catch2/catch_test_macros.hpp>

#include <poll.h>
#include <fcntl.h>

using mdnspp::detail::wakeup_fd;
using mdnspp::detail::native_socket_t;

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
