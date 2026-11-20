#ifndef HPP_GUARD_MDNSPP_INPROC_INPROC_SOCKET_H
#define HPP_GUARD_MDNSPP_INPROC_INPROC_SOCKET_H

#include "mdnspp/endpoint.h"
#include "mdnspp/policy.h"
#include "mdnspp/socket_options.h"

#include "mdnspp/detail/compat.h"

#include "mdnspp/inproc/inproc_bus.h"
#include "mdnspp/inproc/inproc_executor.h"
#include "mdnspp/inproc/inproc_socket_options.h"

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
    struct checked
    {
    };

public:
    explicit inproc_socket(inproc_executor<Clock> &ex)
        : inproc_socket(checked{}, ex, inproc_socket_options{}, std::error_code{})
    {
    }

    explicit inproc_socket(inproc_executor<Clock> &ex, std::error_code &ec)
        : inproc_socket(ex, inproc_socket_options{}, ec)
    {
    }

    explicit inproc_socket(inproc_executor<Clock> &ex, const inproc_socket_options &opts)
        : inproc_socket(checked{}, ex, opts, std::error_code{})
    {
    }

    explicit inproc_socket(inproc_executor<Clock> &ex, const inproc_socket_options &opts, std::error_code &ec)
        : m_bus(&ex.bus())
        , m_opts(opts)
        , m_ep(m_bus->register_socket(this, opts))
        , m_closed(false)
    {
        ec.clear();
    }

    ~inproc_socket()
    {
        close();
    }

    inproc_socket(const inproc_socket &) = delete;
    inproc_socket &operator=(const inproc_socket &) = delete;
    inproc_socket(inproc_socket &&) = delete;
    inproc_socket &operator=(inproc_socket &&) = delete;

    void async_receive(move_only_function<void(std::error_code, const recv_metadata &, std::span<std::byte>)> handler)
    {
        if(m_closed)
            return;
        if(!m_recv_queue.empty())
        {
            auto [data, from, ttl] = std::move(m_recv_queue.front());
            m_recv_queue.pop();
            recv_metadata meta{from, ttl};
            handler(std::error_code{}, meta, std::span<std::byte>(data));
        }
        else
        {
            m_pending_receive = std::move(handler);
        }
    }

    void send(const endpoint &dest, std::span<const std::byte> data)
    {
        std::error_code ec;
        send(dest, data, ec);
        if(ec)
            throw std::system_error(ec, "mdnspp::inproc::inproc_socket::send");
    }

    void send(const endpoint &dest, std::span<const std::byte> data, std::error_code &ec)
    {
        ec.clear();
        if(m_bus)
            m_bus->enqueue(m_ep, dest, data);
    }

    void close() noexcept
    {
        m_closed = true;
        m_pending_receive = nullptr;
        m_recv_queue = {};
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
        if(m_closed)
            return;
        if(m_pending_receive)
        {
            m_recv_buf.assign(data.begin(), data.end());
            recv_metadata meta{from, ttl};
            auto h = std::exchange(m_pending_receive, nullptr);
            h(std::error_code{}, meta, std::span<std::byte>(m_recv_buf));
        }
        else
        {
            m_recv_queue.push({std::vector<std::byte>(data.begin(), data.end()), from, ttl});
        }
    }

    const endpoint &assigned_endpoint() const noexcept { return m_ep; }
    const inproc_socket_options &options() const noexcept { return m_opts; }

private:
    inproc_bus<Clock> *m_bus;
    inproc_socket_options m_opts;
    endpoint m_ep;
    bool m_closed;
    move_only_function<void(std::error_code, const recv_metadata &, std::span<std::byte>)> m_pending_receive;
    std::vector<std::byte> m_recv_buf;

    struct queued_packet
    {
        std::vector<std::byte> data;
        endpoint from;
        std::optional<uint8_t> ttl;
    };

    std::queue<queued_packet> m_recv_queue;

    inproc_socket(checked, inproc_executor<Clock> &ex, const inproc_socket_options &opts, std::error_code ec)
        : inproc_socket(ex, opts, ec)
    {
        if(ec)
            throw std::system_error(ec, "mdnspp::inproc::inproc_socket");
    }
};

}

#endif
