#ifndef HPP_GUARD_MDNSPP_INPROC_INPROC_SOCKET_H
#define HPP_GUARD_MDNSPP_INPROC_INPROC_SOCKET_H

#include "mdnspp/endpoint.h"
#include "mdnspp/policy.h"
#include "mdnspp/socket_options.h"

#include "mdnspp/detail/compat.h"
#include "mdnspp/inproc/inproc_bus.h"
#include "mdnspp/inproc/inproc_executor.h"

#include <span>
#include <queue>
#include <vector>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <system_error>
#include <utility>

namespace mdnspp::inproc {

template <typename Clock = std::chrono::steady_clock>
class inproc_socket
{
public:
    explicit inproc_socket(inproc_executor<Clock> &ex)
        : inproc_socket(ex, socket_options{})
    {
    }

    explicit inproc_socket(inproc_executor<Clock> &ex, std::error_code &)
        : inproc_socket(ex, socket_options{})
    {
    }

    explicit inproc_socket(inproc_executor<Clock> &ex, const socket_options &opts)
        : m_bus(&ex.bus())
        , m_opts(opts)
        , m_ep(m_bus->register_socket(this, opts))
    {
    }

    explicit inproc_socket(inproc_executor<Clock> &ex, const socket_options &opts, std::error_code &)
        : inproc_socket(ex, opts)
    {
    }

    ~inproc_socket()
    {
        close();
    }

    inproc_socket(const inproc_socket &) = delete;
    inproc_socket &operator=(const inproc_socket &) = delete;
    inproc_socket(inproc_socket &&) = delete;
    inproc_socket &operator=(inproc_socket &&) = delete;

    void async_receive(detail::move_only_function<void(const recv_metadata &, std::span<std::byte>)> handler)
    {
        if(!m_recv_queue.empty())
        {
            auto [data, from, ttl] = std::move(m_recv_queue.front());
            m_recv_queue.pop();
            recv_metadata meta{from, ttl};
            handler(meta, std::span<std::byte>(data));
        }
        else
        {
            m_pending_receive = std::move(handler);
        }
    }

    void send(const endpoint &dest, std::span<const std::byte> data)
    {
        if(m_bus)
            m_bus->enqueue(m_ep, dest, data);
    }

    void send(const endpoint &dest, std::span<const std::byte> data, std::error_code &ec)
    {
        ec.clear();
        send(dest, data);
    }

    void close() noexcept
    {
        if(m_bus)
        {
            m_bus->deregister_socket(this);
            m_bus = nullptr;
        }
    }

    void deliver(const endpoint &from, std::span<const std::byte> data)
    {
        deliver(from, data, std::optional<uint8_t>{uint8_t{255}});
    }

    void deliver(const endpoint &from, std::span<const std::byte> data, uint8_t ttl)
    {
        deliver(from, data, std::optional<uint8_t>{ttl});
    }

    void deliver(const endpoint &from, std::span<const std::byte> data, std::optional<uint8_t> ttl)
    {
        if(m_pending_receive)
        {
            m_recv_buf.assign(data.begin(), data.end());
            recv_metadata meta{from, ttl};
            auto h = std::exchange(m_pending_receive, nullptr);
            h(meta, std::span<std::byte>(m_recv_buf));
        }
        else
        {
            m_recv_queue.push({std::vector<std::byte>(data.begin(), data.end()), from, ttl});
        }
    }

    [[nodiscard]] const endpoint &assigned_endpoint() const noexcept { return m_ep; }
    [[nodiscard]] const socket_options &options() const noexcept { return m_opts; }

private:
    inproc_bus<Clock> *m_bus;
    socket_options m_opts;
    endpoint m_ep;
    detail::move_only_function<void(const recv_metadata &, std::span<std::byte>)> m_pending_receive;
    std::vector<std::byte> m_recv_buf;

    struct queued_packet
    {
        std::vector<std::byte> data;
        endpoint from;
        std::optional<uint8_t> ttl;
    };

    std::queue<queued_packet> m_recv_queue;
};

}

#endif
