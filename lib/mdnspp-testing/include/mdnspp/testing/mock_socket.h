#ifndef HPP_GUARD_MDNSPP_TESTING_MOCK_SOCKET_H
#define HPP_GUARD_MDNSPP_TESTING_MOCK_SOCKET_H

#include "mdnspp/testing/mock_executor.h"
#include "mdnspp/testing/mock_receive_queue.h"

#include "mdnspp/policy.h"
#include "mdnspp/endpoint.h"
#include "mdnspp/socket_options.h"

#include <span>
#include <vector>
#include <cstddef>
#include <utility>
#include <system_error>

namespace mdnspp::testing {

struct sent_packet
{
    endpoint dest;
    std::vector<std::byte> data;
};

class mock_socket
{
    struct checked
    {
    };

public:
    mock_socket()
        : m_closed{false}
        , m_opts{}
        , m_receive()
        , m_sent_packets()
    {
    }

    explicit mock_socket(mock_executor &ex)
        : mock_socket(checked{}, ex, socket_options{}, std::error_code{})
    {
    }

    explicit mock_socket(mock_executor &ex, std::error_code &ec)
        : mock_socket(ex, socket_options{}, ec)
    {
    }

    explicit mock_socket(mock_executor &ex, const socket_options &opts)
        : mock_socket(checked{}, ex, opts, std::error_code{})
    {
    }

    explicit mock_socket(mock_executor &, const socket_options &opts, std::error_code &ec)
        : m_closed{false}
        , m_opts{opts}
        , m_receive()
        , m_sent_packets()
    {
        if(s_fail_on_construct)
            ec = std::make_error_code(std::errc::address_not_available);
        else
            ec.clear();
    }

    const socket_options &options() const noexcept { return m_opts; }

    static void set_fail_on_construct(bool v) noexcept { s_fail_on_construct = v; }
    static bool fail_on_construct() noexcept { return s_fail_on_construct; }

    static void set_fail_on_send(bool v) noexcept { s_fail_on_send = v; }
    static bool fail_on_send() noexcept { return s_fail_on_send; }

    recv_metadata default_metadata() const { return default_receive_metadata(m_opts.multicast_group); }

    void enqueue(std::vector<std::byte> packet) { m_receive.push(std::move(packet), default_metadata()); }

    void enqueue(std::vector<std::byte> packet, endpoint from)
    {
        m_receive.push(std::move(packet), sent_from(std::move(from)));
    }

    void enqueue(std::vector<std::byte> packet, recv_metadata meta)
    {
        m_receive.push(std::move(packet), std::move(meta));
    }

    void async_receive(move_only_function<void(std::error_code, const recv_metadata &, std::span<std::byte>)> handler)
    {
        if(!m_closed)
            m_receive.receive(std::move(handler));
    }

    void inject_receive(endpoint from, std::vector<std::byte> packet)
    {
        inject_receive(sent_from(std::move(from)), std::move(packet));
    }

    void inject_receive(recv_metadata meta, std::vector<std::byte> packet)
    {
        if(!m_closed)
            m_receive.inject(std::move(meta), std::move(packet));
    }

    void inject_error(std::error_code ec)
    {
        if(!m_closed)
            m_receive.inject_error(ec);
    }

    bool has_pending_receive() const noexcept { return m_receive.has_pending(); }

    void send(const endpoint &dest, std::span<const std::byte> data)
    {
        std::error_code ec;
        send(dest, data, ec);
        if(ec)
            throw std::system_error(ec, "mdnspp::testing::mock_socket::send");
    }

    void send(const endpoint &dest, std::span<const std::byte> data, std::error_code &ec)
    {
        if(s_fail_on_send)
        {
            ec = std::make_error_code(std::errc::network_unreachable);
            return;
        }
        ec.clear();
        m_sent_packets.push_back(sent_packet{dest, std::vector<std::byte>(data.begin(), data.end())});
    }

    void close() noexcept
    {
        m_closed = true;
        m_receive.cancel();
    }

    const std::vector<sent_packet> &sent_packets() const { return m_sent_packets; }
    bool queue_empty() const { return m_receive.empty(); }
    void clear_sent() { m_sent_packets.clear(); }

private:
    bool m_closed;
    socket_options m_opts;
    mock_receive_queue m_receive;
    std::vector<sent_packet> m_sent_packets;

    static inline bool s_fail_on_construct{false};
    static inline bool s_fail_on_send{false};

    recv_metadata sent_from(endpoint from) const
    {
        recv_metadata meta = default_metadata();
        meta.sender = std::move(from);
        return meta;
    }

    mock_socket(checked, mock_executor &ex, const socket_options &opts, std::error_code ec)
        : mock_socket(ex, opts, ec)
    {
        if(ec)
            throw std::system_error(ec, "mdnspp::testing::mock_socket");
    }
};

}

#endif
