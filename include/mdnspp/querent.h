#ifndef HPP_GUARD_MDNSPP_QUERENT_H
#define HPP_GUARD_MDNSPP_QUERENT_H

#include "mdnspp/socket_policy.h"
#include "mdnspp/timer_policy.h"
#include "mdnspp/records.h"
#include "mdnspp/mdns_error.h"
#include "mdnspp/endpoint.h"

#include <algorithm>
#include <expected>
#include <functional>
#include <memory>
#include <string>
#include <vector>
#include <chrono>
#include <string_view>
#include <cstdint>
#include <cassert>

// These private headers are available via the src/ include directory
// (added as PRIVATE to each test target in CMakeLists.txt)
#include "mdnspp/recv_loop.h"
#include "mdnspp/dns_wire.h"

namespace mdnspp {

template <SocketPolicy S, TimerPolicy T>
class querent
{
public:
    /// Optional callback invoked per record as results arrive during a query.
    using record_callback = std::function<void(const mdns_record_variant &, endpoint)>;

    // Factory function (API-03): construction cannot fail in Phase 4, but
    // std::expected is required by the API contract for future extensibility.
    [[nodiscard]] static std::expected<querent, mdns_error>
    create(S socket, T timer, std::chrono::milliseconds silence_timeout,
           record_callback on_record = {})
    {
        return querent(std::move(socket), std::move(timer),
                       silence_timeout, std::move(on_record));
    }

    // Non-copyable (owns recv_loop by unique_ptr)
    querent(const querent &) = delete;
    querent &operator=(const querent &) = delete;

    // Movable only before query() is called (m_loop must be null).
    querent(querent &&other) noexcept
        : m_socket(std::move(other.m_socket))
        , m_timer(std::move(other.m_timer))
        , m_silence_timeout(other.m_silence_timeout)
        , m_on_record(std::move(other.m_on_record))
        , m_loop(std::move(other.m_loop))
        , m_results(std::move(other.m_results))
    {
        assert(other.m_loop == nullptr); // source must not have been started
    }

    querent &operator=(querent &&) = delete;

    ~querent()
    {
        m_loop.reset(); // destroyed before m_socket/m_timer (reverse declaration order)
    }

    // Test accessors: access to the internal socket (mirrors
    // recv_loop::timer() and service_discovery::socket() patterns).
    const S &socket() const noexcept
    {
        return m_loop ? m_loop->socket() : m_socket;
    }
    S &socket() noexcept
    {
        return m_loop ? m_loop->socket() : m_socket;
    }

    // Sends a DNS query for name/qtype, arms recv_loop to accumulate records.
    // Results are available via results() after io.run() returns.
    // Must only be called once per lifetime (one query per instance).
    void query(std::string_view name, uint16_t qtype)
    {
        assert(m_loop == nullptr); // one query per lifetime
        m_results.clear();
        m_query_name = std::string(name);

        // Build and send DNS query for the requested name and qtype
        auto query_bytes = detail::build_dns_query(name, qtype);
        m_socket.send(endpoint{"224.0.0.251", 5353},
                      std::span<const std::byte>(query_bytes));

        m_loop = std::make_unique<recv_loop<S, T>>(
            m_socket,
            m_timer,
            m_silence_timeout,
            // on_packet: walk frame into temp, keep all records from packets
            // that contain at least one record matching the queried name.
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
                            return r.name == m_query_name;
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
    querent(S socket, T timer, std::chrono::milliseconds silence_timeout,
            record_callback on_record)
        : m_socket(std::move(socket))
        , m_timer(std::move(timer))
        , m_silence_timeout(silence_timeout)
        , m_on_record(std::move(on_record))
        , m_loop(nullptr)
    {
    }

    S m_socket;
    T m_timer;
    std::chrono::milliseconds m_silence_timeout;
    record_callback m_on_record;             // optional per-record callback
    std::string m_query_name;                // set in query(), used for filtering
    std::unique_ptr<recv_loop<S, T>> m_loop; // null until query()
    std::vector<mdns_record_variant> m_results;
};

} // namespace mdnspp

#endif // HPP_GUARD_MDNSPP_QUERENT_H
