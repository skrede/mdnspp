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
#include <functional>
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

class MockSocket
{
public:
    // Default constructor — backward compatibility during transition (removed in Plan 03).
    MockSocket() = default;

    // Concept-satisfying constructors — take mock_executor& (no-op).
    explicit MockSocket(mock_executor &)
    {
    }

    explicit MockSocket(mock_executor &, std::error_code &ec)
    {
        if(s_fail_on_construct)
            ec = std::make_error_code(std::errc::address_not_available);
    }

    explicit MockSocket(mock_executor &, const socket_options &opts)
        : m_opts{opts}
    {
    }

    explicit MockSocket(mock_executor &, const socket_options &opts, std::error_code &ec)
        : m_opts{opts}
    {
        if(s_fail_on_construct)
            ec = std::make_error_code(std::errc::address_not_available);
    }

    const socket_options &options() const noexcept { return m_opts; }

    // Failure injection: set before construction to trigger error in (executor, ec) constructor.
    static void set_fail_on_construct(bool v) noexcept { s_fail_on_construct = v; }
    static bool fail_on_construct() noexcept { return s_fail_on_construct; }

    // Enqueue a packet with a specific sender endpoint.
    void enqueue(std::vector<std::byte> packet, endpoint from)
    {
        m_receive_queue.push({std::move(packet), std::move(from)});
    }

    // Enqueue a packet with the default sender (endpoint{}).
    void enqueue(std::vector<std::byte> packet)
    {
        enqueue(std::move(packet), endpoint{});
    }

    void async_receive(std::function<void(const endpoint &, std::span<std::byte>)> handler)
    {
        if(!m_receive_queue.empty())
        {
            auto [packet, sender] = std::move(m_receive_queue.front());
            m_receive_queue.pop();
            handler(std::move(sender), std::span<std::byte>(packet));
        }
    }

    void send(const endpoint &dest, std::span<const std::byte> data)
    {
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
    std::queue<std::pair<std::vector<std::byte>, endpoint>> m_receive_queue;
    std::vector<sent_packet> m_sent_packets;
    socket_options m_opts{};

    static inline bool s_fail_on_construct{false};
};

class MockTimer
{
public:
    // Default constructor — backward compatibility during transition (removed in Plan 03).
    MockTimer() = default;

    // Concept-satisfying constructors — take mock_executor& (no-op).
    explicit MockTimer(mock_executor &)
    {
    }

    explicit MockTimer(mock_executor &, std::error_code &)
    {
    }

    void expires_after(std::chrono::milliseconds)
    {
        m_pending_handler = nullptr;
        m_cancel_count++;
    }

    void async_wait(std::function<void(std::error_code)> handler)
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

private:
    std::function<void(std::error_code)> m_pending_handler;
    int m_cancel_count{0};
};

struct MockPolicy
{
    using executor_type = mock_executor &;
    using socket_type = MockSocket;
    using timer_type = MockTimer;

    static void post(executor_type ex, detail::move_only_function<void()> fn)
    {
        ex.m_posted.push_back(std::move(fn));
    }
};

}

static_assert(mdnspp::Policy<mdnspp::testing::MockPolicy>, "MockPolicy must satisfy Policy concept");

#endif
