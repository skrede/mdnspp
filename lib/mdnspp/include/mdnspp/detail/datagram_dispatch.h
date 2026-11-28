#ifndef HPP_GUARD_MDNSPP_DETAIL_DATAGRAM_DISPATCH_H
#define HPP_GUARD_MDNSPP_DETAIL_DATAGRAM_DISPATCH_H

#include "mdnspp/detail/poll_set.h"
#include "mdnspp/detail/native_socket.h"
#include "mdnspp/detail/recv_datagram.h"
#include "mdnspp/detail/socket_registry.h"

#include "mdnspp/policy.h"

#include <span>
#include <array>
#include <memory>
#include <vector>
#include <cstddef>
#include <cstdint>
#include <system_error>

namespace mdnspp::detail {

class datagram_dispatcher
{
    // Each nesting level owns its storage, so an outer handler's span survives a nested poll.
    struct receive_level
    {
        recv_metadata meta;
        std::array<std::byte, max_udp_payload> buf;
    };

    class depth_guard
    {
    public:
        explicit depth_guard(uint32_t &depth)
            : m_depth{depth}
        {
            ++m_depth;
        }

        ~depth_guard()
        {
            --m_depth;
        }

        depth_guard(const depth_guard &) = delete;
        depth_guard &operator=(const depth_guard &) = delete;

    private:
        uint32_t &m_depth;
    };

public:
    explicit datagram_dispatcher(socket_registry &sockets)
        : m_depth{0}
        , m_generation{0}
        , m_sockets{sockets}
        , m_ready{}
        , m_levels{}
    {
        m_levels.push_back(make_level());
    }

    bool dispatch(const poll_set &poll)
    {
        const depth_guard guard{m_depth};
        receive_level &level = current_level();
        poll.ready_sockets(m_ready);
        const bool any_ready = !m_ready.empty();
        const uint64_t generation = ++m_generation;
        // A handler that polls re-entrantly refills m_ready and services it, so this walk must not continue.
        for(std::size_t i = 0; m_generation == generation && i < m_ready.size(); ++i)
            deliver(m_ready[i], level);
        return any_ready;
    }

private:
    uint32_t m_depth;
    uint64_t m_generation;
    socket_registry &m_sockets;
    std::vector<ready_socket> m_ready;
    std::vector<std::unique_ptr<receive_level>> m_levels;

    static std::unique_ptr<receive_level> make_level()
    {
        std::unique_ptr<receive_level> level = std::make_unique<receive_level>();
        level->meta = reserved_metadata();
        return level;
    }

    static bool error_only(int16_t revents) noexcept
    {
        return (revents & POLLIN) == 0 && (revents & (POLLERR | POLLHUP)) != 0;
    }

    receive_level &current_level()
    {
        if(m_levels.size() < m_depth)
            m_levels.push_back(make_level());
        return *m_levels[m_depth - 1];
    }

    void deliver(const ready_socket &ready, receive_level &level)
    {
        if(!m_sockets.armed(ready.fd))
            return;
        if((ready.revents & POLLNVAL) != 0)
            return fail(ready.fd, std::make_error_code(std::errc::bad_file_descriptor));
        const datagram_result result = read_datagram(ready.fd, level);
        if(result.would_block && error_only(ready.revents))
            return fail(ready.fd, std::make_error_code(std::errc::io_error));
        if(result.would_block || result.truncated)
            return;
        if(result.ec)
            return fail(ready.fd, result.ec);
        receive_handler handler = m_sockets.take_handler(ready.fd);
        handler(std::error_code{}, level.meta, std::span<std::byte>{level.buf.data(), result.size});
    }

    void fail(native_socket_t fd, std::error_code ec)
    {
        receive_handler handler = m_sockets.take_handler(fd);
        handler(ec, recv_metadata{}, std::span<std::byte>{});
    }

    datagram_result read_datagram(native_socket_t fd, receive_level &level)
    {
#ifdef _WIN32
        return recv_datagram(fd, level.buf, m_sockets.wsarecvmsg(fd), level.meta);
#else
        return recv_datagram(fd, level.buf, level.meta);
#endif
    }
};

}

#endif
