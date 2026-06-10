#ifndef HPP_GUARD_MDNSPP_TESTING_MOCK_POLICY_H
#define HPP_GUARD_MDNSPP_TESTING_MOCK_POLICY_H

#include "mdnspp/policy.h"
#include "mdnspp/endpoint.h"
#include "mdnspp/socket_options.h"
#include "mdnspp/detail/compat.h"

#include <deque>
#include <span>
#include <queue>
#include <chrono>
#include <vector>
#include <cstddef>
#include <utility>
#include <system_error>

namespace mdnspp::testing {

struct mock_executor
{
    std::deque<detail::move_only_function<void()>> m_posted;

    void drain_posted()
    {
        while (!m_posted.empty())
        {
            auto fn = std::move(m_posted.front());
            m_posted.pop_front();
            fn();
        }
    }
};

struct sent_packet
{
    endpoint dest;
    std::vector<std::byte> data;
};

class mock_socket
{
public:
    // Default constructor — backward compatibility.
    mock_socket() = default;

    // Concept-satisfying constructors — take mock_executor& (no-op).
    explicit mock_socket(mock_executor &)
    {
    }

    explicit mock_socket(mock_executor &, std::error_code &ec)
    {
        if(s_fail_on_construct)
            ec = std::make_error_code(std::errc::address_not_available);
    }

    explicit mock_socket(mock_executor &, const socket_options &opts)
        : m_opts{opts}
    {
    }

    explicit mock_socket(mock_executor &, const socket_options &opts, std::error_code &ec)
        : m_opts{opts}
    {
        if(s_fail_on_construct)
            ec = std::make_error_code(std::errc::address_not_available);
    }

    const socket_options &options() const noexcept { return m_opts; }

    // Failure injection: set before construction to trigger error in (executor, ec) constructor.
    static void set_fail_on_construct(bool v) noexcept { s_fail_on_construct = v; }
    static bool fail_on_construct() noexcept { return s_fail_on_construct; }

    // Failure injection: set before send to trigger error in ec send overload.
    static void set_fail_on_send(bool v) noexcept { s_fail_on_send = v; }
    static bool fail_on_send() noexcept { return s_fail_on_send; }

    // Enqueue a packet with a specific sender endpoint.
    void enqueue(std::vector<std::byte> packet, endpoint from)
    {
        m_receive_queue.push({std::move(packet), std::move(from), std::optional<uint8_t>{uint8_t{255}}});
    }

    // Enqueue a packet with the default sender (endpoint{}).
    void enqueue(std::vector<std::byte> packet)
    {
        enqueue(std::move(packet), endpoint{});
    }

    // Enqueue a packet with a specific sender and optional TTL.
    void enqueue(std::vector<std::byte> packet, endpoint from, std::optional<uint8_t> ttl)
    {
        m_receive_queue.push({std::move(packet), std::move(from), ttl});
    }

    void async_receive(move_only_function<void(std::error_code, const recv_metadata &, std::span<std::byte>)> handler)
    {
        if(!m_receive_queue.empty())
        {
            auto [packet, sender, ttl] = std::move(m_receive_queue.front());
            m_receive_queue.pop();
            recv_metadata meta{std::move(sender), ttl};
            handler(std::error_code{}, meta, std::span<std::byte>(packet));
        }
        else
        {
            m_pending_receive = std::move(handler);
        }
    }

    // Inject a packet during live state: enqueue and trigger the pending receive handler.
    // Use this when the server is already running and the recv_loop chain has stalled.
    void inject_receive(endpoint from, std::vector<std::byte> packet)
    {
        inject_receive(std::move(from), std::move(packet), std::optional<uint8_t>{uint8_t{255}});
    }

    // Inject a packet with an explicit optional TTL.
    void inject_receive(endpoint from, std::vector<std::byte> packet, std::optional<uint8_t> ttl)
    {
        if(m_pending_receive)
        {
            auto h = std::exchange(m_pending_receive, nullptr);
            recv_metadata meta{std::move(from), ttl};
            h(std::error_code{}, meta, std::span<std::byte>(packet));
        }
        else
        {
            enqueue(std::move(packet), std::move(from), ttl);
        }
    }

    // Deliver a receive error to the pending handler, simulating a socket-level failure.
    void inject_error(std::error_code ec)
    {
        if(m_pending_receive)
        {
            auto h = std::exchange(m_pending_receive, nullptr);
            h(ec, recv_metadata{}, std::span<std::byte>{});
        }
    }

    bool has_pending_receive() const noexcept { return m_pending_receive != nullptr; }

    void send(const endpoint &dest, std::span<const std::byte> data)
    {
        m_sent_packets.push_back(sent_packet{
            dest,
            std::vector<std::byte>(data.begin(), data.end())
        });
    }

    void send(const endpoint &dest, std::span<const std::byte> data, std::error_code &ec)
    {
        if(s_fail_on_send)
        {
            ec = std::make_error_code(std::errc::network_unreachable);
            return;
        }
        ec.clear();
        m_sent_packets.push_back(sent_packet{
            dest,
            std::vector<std::byte>(data.begin(), data.end())
        });
    }

    void close() noexcept
    {
    }

    const std::vector<sent_packet> &sent_packets() const { return m_sent_packets; }
    bool queue_empty() const { return m_receive_queue.empty(); }
    void clear_sent() { m_sent_packets.clear(); }

private:
    struct queued_item
    {
        std::vector<std::byte> packet;
        endpoint sender;
        std::optional<uint8_t> ttl;
    };
    std::queue<queued_item> m_receive_queue;
    move_only_function<void(std::error_code, const recv_metadata &, std::span<std::byte>)> m_pending_receive;
    std::vector<sent_packet> m_sent_packets;
    socket_options m_opts{};

    static inline bool s_fail_on_construct{false};
    static inline bool s_fail_on_send{false};
};

class mock_timer
{
public:
    // Default constructor — backward compatibility.
    mock_timer() = default;

    // Concept-satisfying constructors — take mock_executor& (no-op).
    explicit mock_timer(mock_executor &)
    {
    }

    explicit mock_timer(mock_executor &, std::error_code &)
    {
    }

    void expires_after(std::chrono::milliseconds d)
    {
        m_last_duration = d;
        m_pending_handler = nullptr;
        m_cancel_count++;
    }

    void async_wait(detail::move_only_function<void(std::error_code)> handler)
    {
        m_pending_handler = std::move(handler);
    }

    void cancel()
    {
        m_cancel_count++;
        if(m_pending_handler)
        {
            auto h = std::exchange(m_pending_handler, nullptr);
            h(std::make_error_code(std::errc::operation_canceled));
        }
    }

    // Test control: simulate the silence timeout expiring naturally.
    void fire()
    {
        if(m_pending_handler)
        {
            auto h = std::exchange(m_pending_handler, nullptr);
            h(std::error_code{});
        }
    }

    int cancel_count() const { return m_cancel_count; }
    bool has_pending() const { return m_pending_handler != nullptr; }
    std::chrono::milliseconds last_duration() const { return m_last_duration; }

private:
    detail::move_only_function<void(std::error_code)> m_pending_handler;
    std::chrono::milliseconds m_last_duration{0};
    int m_cancel_count{0};
};

struct mock_policy
{
    using executor_type = mock_executor &;
    using socket_type = mock_socket;
    using timer_type = mock_timer;

    static void post(executor_type ex, detail::move_only_function<void()> fn)
    {
        ex.m_posted.push_back(std::move(fn));
    }
};

}

static_assert(mdnspp::policy_like<mdnspp::testing::mock_policy>, "mock_policy must satisfy Policy concept");

#endif
