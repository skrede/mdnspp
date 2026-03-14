#ifndef HPP_GUARD_MDNSPP_LOCAL_LOCAL_SOCKET_H
#define HPP_GUARD_MDNSPP_LOCAL_LOCAL_SOCKET_H

#include "mdnspp/endpoint.h"
#include "mdnspp/policy.h"
#include "mdnspp/socket_options.h"

#include "mdnspp/local/local_bus.h"
#include "mdnspp/local/local_executor.h"

#include <span>
#include <queue>
#include <vector>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <system_error>
#include <utility>

namespace mdnspp::local {

template <typename Clock = std::chrono::steady_clock>
class local_socket
{
public:
    explicit local_socket(local_executor<Clock> &ex)
        : local_socket(ex, socket_options{})
    {
    }

    explicit local_socket(local_executor<Clock> &ex, std::error_code &)
        : local_socket(ex, socket_options{})
    {
    }

    explicit local_socket(local_executor<Clock> &ex, const socket_options &opts)
        : m_bus(&ex.bus())
        , m_opts(opts)
        , m_ep(m_bus->register_socket(this, opts))
    {
    }

    explicit local_socket(local_executor<Clock> &ex, const socket_options &opts, std::error_code &)
        : local_socket(ex, opts)
    {
    }

    ~local_socket()
    {
        close();
    }

    local_socket(const local_socket &) = delete;
    local_socket &operator=(const local_socket &) = delete;
    local_socket(local_socket &&) = delete;
    local_socket &operator=(local_socket &&) = delete;

    void async_receive(std::function<void(const recv_metadata &, std::span<std::byte>)> handler)
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
        deliver(from, data, uint8_t{255});
    }

    void deliver(const endpoint &from, std::span<const std::byte> data, uint8_t ttl)
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
    local_bus<Clock> *m_bus;
    socket_options m_opts;
    endpoint m_ep;
    std::function<void(const recv_metadata &, std::span<std::byte>)> m_pending_receive;
    std::vector<std::byte> m_recv_buf;

    struct queued_packet
    {
        std::vector<std::byte> data;
        endpoint from;
        uint8_t ttl;
    };

    std::queue<queued_packet> m_recv_queue;
};

}

#endif
