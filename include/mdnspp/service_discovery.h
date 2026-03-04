#ifndef HPP_GUARD_MDNSPP_SERVICE_DISCOVERY_H
#define HPP_GUARD_MDNSPP_SERVICE_DISCOVERY_H

#include "mdnspp/policy.h"
#include "mdnspp/records.h"
#include "mdnspp/endpoint.h"

#include <algorithm>
#include <functional>
#include <memory>
#include <string>
#include <vector>
#include <chrono>
#include <string_view>
#include <cassert>

// These private headers are available via the src/ include directory
// (added as PRIVATE to each test target in CMakeLists.txt)
#include "mdnspp/recv_loop.h"
#include "mdnspp/dns_wire.h"

namespace mdnspp {

template <Policy P>
class service_discovery
{
public:
    using executor_type   = typename P::executor_type;
    using socket_type     = typename P::socket_type;
    using timer_type      = typename P::timer_type;

    /// Optional callback invoked per record as results arrive during discovery.
    using record_callback = std::function<void(const mdns_record_variant &, endpoint)>;

    // Non-copyable (owns recv_loop by unique_ptr)
    service_discovery(const service_discovery &) = delete;
    service_discovery &operator=(const service_discovery &) = delete;

    // Movable only before discover() is called (m_loop must be null).
    service_discovery(service_discovery &&other) noexcept
        : m_socket(std::move(other.m_socket))
        , m_timer(std::move(other.m_timer))
        , m_silence_timeout(other.m_silence_timeout)
        , m_on_record(std::move(other.m_on_record))
        , m_loop(std::move(other.m_loop))
        , m_results(std::move(other.m_results))
    {
        assert(other.m_loop == nullptr); // source must not have been started
    }

    service_discovery &operator=(service_discovery &&) = delete;

    ~service_discovery()
    {
        m_loop.reset();
    }

    // Throwing constructor — constructs socket and timer from executor.
    // Silence timeout determines how long to wait after the last relevant packet
    // before stopping the recv_loop.
    explicit service_discovery(executor_type ex,
                               std::chrono::milliseconds silence_timeout,
                               record_callback on_record = {})
        : m_socket(ex)
        , m_timer(ex)
        , m_silence_timeout(silence_timeout)
        , m_on_record(std::move(on_record))
        , m_loop(nullptr)
    {
    }

    // Non-throwing constructors — ec is last (ASIO convention).
    service_discovery(executor_type ex,
                      std::chrono::milliseconds silence_timeout,
                      record_callback on_record,
                      std::error_code &ec)
        : m_socket(ex, ec)
        , m_timer(ex)
        , m_silence_timeout(silence_timeout)
        , m_on_record(std::move(on_record))
        , m_loop(nullptr)
    {
    }

    service_discovery(executor_type ex,
                      std::chrono::milliseconds silence_timeout,
                      std::error_code &ec)
        : m_socket(ex, ec)
        , m_timer(ex)
        , m_silence_timeout(silence_timeout)
        , m_loop(nullptr)
    {
    }

    // Accessors — service_discovery owns socket and timer directly.
    const socket_type &socket() const noexcept { return m_socket; }
    socket_type       &socket()       noexcept { return m_socket; }
    const timer_type  &timer()  const noexcept { return m_timer; }
    timer_type        &timer()        noexcept { return m_timer; }

    // Sends a DNS PTR query for service_type, arms recv_loop to accumulate records.
    // Results are available via results() after io.run() returns.
    // Must only be called once per lifetime (one discover per instance).
    void discover(std::string_view service_type)
    {
        assert(m_loop == nullptr); // one discover per lifetime
        m_results.clear();
        m_service_type = std::string(service_type);

        // Build and send DNS PTR query (qtype = 12)
        auto query_bytes = detail::build_dns_query(service_type, 12);
        m_socket.send(endpoint{"224.0.0.251", 5353},
                      std::span<const std::byte>(query_bytes));

        m_loop = std::make_unique<recv_loop<P>>(
            m_socket,
            m_timer,
            m_silence_timeout,
            // on_packet: walk frame into temp, keep all records from packets
            // that contain at least one record matching the queried service type.
            // Returns true (reset timer) only for relevant packets.
            [this](std::span<std::byte> data, endpoint sender) -> bool
            {
                std::vector<mdns_record_variant> batch;
                detail::walk_dns_frame(
                    std::span<const std::byte>(data.data(), data.size()),
                    sender,
                    [&batch](mdns_record_variant rec)
                    {
                        batch.push_back(std::move(rec));
                    });

                bool relevant = std::any_of(batch.begin(), batch.end(),
                    [this](const mdns_record_variant &rec)
                    {
                        return std::visit([this](const auto &r)
                        {
                            return r.name == m_service_type;
                        }, rec);
                    });

                if (relevant)
                {
                    if (m_on_record)
                    {
                        for (const auto &rec : batch)
                            m_on_record(rec, sender);
                    }
                    m_results.insert(m_results.end(),
                        std::make_move_iterator(batch.begin()),
                        std::make_move_iterator(batch.end()));
                }
                return relevant;
            },
            // on_silence: stop the loop (io.run() returns)
            [this]()
            {
                m_loop->stop();
            });

        m_loop->start();
    }

    // Access accumulated results (populated during io.run()).
    const std::vector<mdns_record_variant> &results() const noexcept
    {
        return m_results;
    }

    // Early termination — stops the recv_loop.
    void stop()
    {
        if (m_loop)
            m_loop->stop();
    }

private:
    socket_type      m_socket;
    timer_type       m_timer;
    std::chrono::milliseconds m_silence_timeout;
    record_callback  m_on_record;            // optional per-record callback
    std::string      m_service_type;         // set in discover(), used for filtering
    std::unique_ptr<recv_loop<P>> m_loop;    // null until discover()
    std::vector<mdns_record_variant> m_results;
};

} // namespace mdnspp

#endif // HPP_GUARD_MDNSPP_SERVICE_DISCOVERY_H
