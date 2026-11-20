#ifndef HPP_GUARD_MDNSPP_TESTING_MOCK_SOCKET_H
#define HPP_GUARD_MDNSPP_TESTING_MOCK_SOCKET_H

#include "mdnspp/testing/mock_executor.h"

#include "mdnspp/policy.h"
#include "mdnspp/endpoint.h"
#include "mdnspp/socket_options.h"

#include <span>
#include <queue>
#include <vector>
#include <cstddef>
#include <cstdint>
#include <utility>
#include <optional>
#include <system_error>

namespace mdnspp::testing {

struct sent_packet
{
    endpoint dest;
    std::vector<std::byte> data;
};

class mock_socket
{
    struct queued_item
    {
        std::vector<std::byte> packet;
        endpoint sender;
        std::optional<uint8_t> ttl;
    };

    struct checked
    {
    };

public:
    mock_socket()
        : m_opts{}
        , m_closed{false}
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
        : m_opts{opts}
        , m_closed{false}
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

    void enqueue(std::vector<std::byte> packet, endpoint from)
    {
        m_receive_queue.push({std::move(packet), std::move(from), std::optional<uint8_t>{uint8_t{255}}});
    }

    void enqueue(std::vector<std::byte> packet)
    {
        enqueue(std::move(packet), endpoint{});
    }

    void enqueue(std::vector<std::byte> packet, endpoint from, std::optional<uint8_t> ttl)
    {
        m_receive_queue.push({std::move(packet), std::move(from), ttl});
    }

    void async_receive(move_only_function<void(std::error_code, const recv_metadata &, std::span<std::byte>)> handler)
    {
        if(m_closed)
            return;
        if(m_receive_queue.empty())
        {
            m_pending_receive = std::move(handler);
            return;
        }
        auto [packet, sender, ttl] = std::move(m_receive_queue.front());
        m_receive_queue.pop();
        recv_metadata meta{std::move(sender), ttl};
        handler(std::error_code{}, meta, std::span<std::byte>(packet));
    }

    void inject_receive(endpoint from, std::vector<std::byte> packet)
    {
        inject_receive(std::move(from), std::move(packet), std::optional<uint8_t>{uint8_t{255}});
    }

    void inject_receive(endpoint from, std::vector<std::byte> packet, std::optional<uint8_t> ttl)
    {
        if(m_closed)
            return;
        if(!m_pending_receive)
        {
            enqueue(std::move(packet), std::move(from), ttl);
            return;
        }
        auto h = std::exchange(m_pending_receive, nullptr);
        recv_metadata meta{std::move(from), ttl};
        h(std::error_code{}, meta, std::span<std::byte>(packet));
    }

    void inject_error(std::error_code ec)
    {
        if(m_closed || !m_pending_receive)
            return;
        auto h = std::exchange(m_pending_receive, nullptr);
        h(ec, recv_metadata{}, std::span<std::byte>{});
    }

    bool has_pending_receive() const noexcept { return m_pending_receive != nullptr; }

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
        m_pending_receive = nullptr;
    }

    const std::vector<sent_packet> &sent_packets() const { return m_sent_packets; }
    bool queue_empty() const { return m_receive_queue.empty(); }
    void clear_sent() { m_sent_packets.clear(); }

private:
    std::queue<queued_item> m_receive_queue;
    move_only_function<void(std::error_code, const recv_metadata &, std::span<std::byte>)> m_pending_receive;
    std::vector<sent_packet> m_sent_packets;
    socket_options m_opts;
    bool m_closed;

    static inline bool s_fail_on_construct{false};
    static inline bool s_fail_on_send{false};

    mock_socket(checked, mock_executor &ex, const socket_options &opts, std::error_code ec)
        : mock_socket(ex, opts, ec)
    {
        if(ec)
            throw std::system_error(ec, "mdnspp::testing::mock_socket");
    }
};

}

#endif
