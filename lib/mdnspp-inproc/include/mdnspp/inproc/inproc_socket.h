#ifndef HPP_GUARD_MDNSPP_INPROC_INPROC_SOCKET_H
#define HPP_GUARD_MDNSPP_INPROC_INPROC_SOCKET_H

#include "mdnspp/inproc/inproc_bus.h"
#include "mdnspp/inproc/inproc_executor.h"
#include "mdnspp/inproc/inproc_socket_options.h"

#include "mdnspp/inproc/detail/inproc_receive_queue.h"

#include "mdnspp/policy.h"
#include "mdnspp/endpoint.h"
#include "mdnspp/socket_options.h"

#include "mdnspp/detail/compat.h"

#include <span>
#include <cstddef>
#include <utility>
#include <system_error>

namespace mdnspp::inproc {

template <typename Clock = std::chrono::steady_clock>
class inproc_socket : public inproc_receiver
{
    struct checked
    {
    };

public:
    static constexpr bool in_process_transport{true};

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
        : m_closed(false)
        , m_bus(&ex.bus())
        , m_ep(m_bus->register_socket(*this, opts, ec))
        , m_opts(opts)
        , m_receive()
    {
        if(ec)
            close();
    }

    ~inproc_socket() override
    {
        close();
    }

    inproc_socket(const inproc_socket &) = delete;
    inproc_socket &operator=(const inproc_socket &) = delete;
    inproc_socket(inproc_socket &&) = delete;
    inproc_socket &operator=(inproc_socket &&) = delete;

    void async_receive(move_only_function<void(std::error_code, const recv_metadata &, std::span<std::byte>)> handler)
    {
        if(!m_closed)
            m_receive.receive(std::move(handler));
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
        if(!m_bus)
        {
            ec = std::make_error_code(std::errc::bad_file_descriptor);
            return;
        }
        ec.clear();
        m_bus->enqueue(m_ep, dest, data);
    }

    void close() noexcept
    {
        m_closed = true;
        m_receive.clear();
        if(m_bus)
        {
            m_bus->deregister_socket(*this);
            m_bus = nullptr;
        }
    }

    void deliver(const endpoint &from, const endpoint &to, std::span<const std::byte> data) override
    {
        deliver(detail::inproc_metadata(from, to), data);
    }

    void deliver(const recv_metadata &meta, std::span<const std::byte> data)
    {
        if(!m_closed)
            m_receive.deliver(meta, data);
    }

    const endpoint &assigned_endpoint() const noexcept { return m_ep; }
    const inproc_socket_options &options() const noexcept { return m_opts; }

private:
    bool m_closed;
    inproc_bus<Clock> *m_bus;
    endpoint m_ep;
    inproc_socket_options m_opts;
    detail::inproc_receive_queue m_receive;

    inproc_socket(checked, inproc_executor<Clock> &ex, const inproc_socket_options &opts, std::error_code ec)
        : inproc_socket(ex, opts, ec)
    {
        if(ec)
            throw std::system_error(ec, "mdnspp::inproc::inproc_socket");
    }
};

}

#endif
