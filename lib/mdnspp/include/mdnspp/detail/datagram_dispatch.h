#ifndef HPP_GUARD_MDNSPP_DETAIL_DATAGRAM_DISPATCH_H
#define HPP_GUARD_MDNSPP_DETAIL_DATAGRAM_DISPATCH_H

#include "mdnspp/detail/poll_set.h"
#include "mdnspp/detail/native_socket.h"
#include "mdnspp/detail/recv_datagram.h"
#include "mdnspp/detail/socket_registry.h"

#include "mdnspp/policy.h"

#include <span>
#include <array>
#include <vector>
#include <cstddef>
#include <cstdint>
#include <system_error>

namespace mdnspp::detail {

class datagram_dispatcher
{
public:
    explicit datagram_dispatcher(socket_registry &sockets)
        : m_generation{0}
        , m_recv_meta(reserved_metadata())
        , m_sockets{sockets}
        , m_ready{}
        , m_recv_buf{}
    {
    }

    bool dispatch(const poll_set &poll)
    {
        poll.ready_sockets(m_ready);
        const bool any_ready = !m_ready.empty();
        const uint64_t generation = ++m_generation;
        // A handler that polls re-entrantly refills m_ready and services it, so this walk must not continue.
        for(std::size_t i = 0; m_generation == generation && i < m_ready.size(); ++i)
            deliver(m_ready[i]);
        return any_ready;
    }

private:
    uint64_t m_generation;
    recv_metadata m_recv_meta;
    socket_registry &m_sockets;
    std::vector<ready_socket> m_ready;
    std::array<std::byte, max_udp_payload> m_recv_buf;

    static bool error_only(int16_t revents) noexcept
    {
        return (revents & POLLIN) == 0 && (revents & (POLLERR | POLLHUP)) != 0;
    }

    void deliver(const ready_socket &ready)
    {
        if(!m_sockets.armed(ready.fd))
            return;
        if((ready.revents & POLLNVAL) != 0)
            return fail(ready.fd, std::make_error_code(std::errc::bad_file_descriptor));
        const datagram_result result = read_datagram(ready.fd);
        if(result.would_block && error_only(ready.revents))
            return fail(ready.fd, std::make_error_code(std::errc::io_error));
        if(result.would_block || result.truncated)
            return;
        if(result.ec)
            return fail(ready.fd, result.ec);
        receive_handler handler = m_sockets.take_handler(ready.fd);
        handler(std::error_code{}, m_recv_meta, std::span<std::byte>{m_recv_buf.data(), result.size});
    }

    void fail(native_socket_t fd, std::error_code ec)
    {
        receive_handler handler = m_sockets.take_handler(fd);
        handler(ec, recv_metadata{}, std::span<std::byte>{});
    }

    datagram_result read_datagram(native_socket_t fd)
    {
#ifdef _WIN32
        return recv_datagram(fd, m_recv_buf, m_sockets.wsarecvmsg(fd), m_recv_meta);
#else
        return recv_datagram(fd, m_recv_buf, m_recv_meta);
#endif
    }
};

}

#endif
