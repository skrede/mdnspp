#include "mdnspp/detail/nic_monitor_netlink.h"

#include <catch2/catch_test_macros.hpp>

#include <span>
#include <cerrno>
#include <cstddef>
#include <cstdint>

namespace {

class scripted_receive
{
public:
    scripted_receive(int32_t data_calls, int32_t enobufs_calls)
        : m_data_calls(data_calls)
        , m_enobufs_calls(enobufs_calls)
        , m_calls(0)
    {
    }

    ssize_t operator()(std::span<std::byte> buffer)
    {
        int32_t call = m_calls++;
        if(call < m_data_calls)
            return static_cast<ssize_t>(buffer.size());
        errno = call < m_data_calls + m_enobufs_calls ? ENOBUFS : EAGAIN;
        return -1;
    }

    int32_t calls() const { return m_calls; }

private:
    int32_t m_data_calls;
    int32_t m_enobufs_calls;
    int32_t m_calls;
};

}

TEST_CASE("netlink drain stops at the first ENOBUFS and reports a change", "[nic_monitor][netlink]")
{
    scripted_receive receive{0, 1000};

    CHECK(mdnspp::detail::drain_netlink(receive));
    CHECK(receive.calls() <= 2);
}

TEST_CASE("netlink drain reads every queued message", "[nic_monitor][netlink]")
{
    scripted_receive receive{2, 0};

    CHECK(mdnspp::detail::drain_netlink(receive));
    CHECK(receive.calls() == 3);
}

TEST_CASE("netlink drain of an empty socket reports no change", "[nic_monitor][netlink]")
{
    scripted_receive receive{0, 0};

    CHECK_FALSE(mdnspp::detail::drain_netlink(receive));
    CHECK(receive.calls() == 1);
}
