#ifndef HPP_GUARD_MDNSPP_QUERENT_H
#define HPP_GUARD_MDNSPP_QUERENT_H

#include "mdnspp/socket_policy.h"
#include "mdnspp/timer_policy.h"
#include "mdnspp/records.h"
#include "mdnspp/mdns_error.h"
#include "mdnspp/endpoint.h"

#include <expected>
#include <vector>
#include <chrono>
#include <string_view>
#include <cstdint>

// These private headers are available via the src/ include directory
// (added as PRIVATE to each test target in CMakeLists.txt)
#include "mdnspp/recv_loop.h"
#include "mdnspp/dns_wire.h"

namespace mdnspp {

template <SocketPolicy S, TimerPolicy T>
class querent
{
public:
    // Factory function (API-03): construction cannot fail in Phase 4, but
    // std::expected is required by the API contract for future extensibility.
    [[nodiscard]] static std::expected<querent, mdns_error>
    create(S socket, T timer, std::chrono::milliseconds silence_timeout)
    {
        return querent(std::move(socket), std::move(timer), silence_timeout);
    }

    // Test accessors: access to the internal socket (mirrors
    // recv_loop::timer() and service_discovery::socket() patterns).
    const S &socket() const noexcept { return m_socket; }
    S &socket() noexcept { return m_socket; }

    // Sends a DNS query for name/qtype, accumulates records received within
    // silence_timeout, and returns them via std::expected.
    std::expected<std::vector<mdns_record_variant>, mdns_error>
    query(std::string_view name, uint16_t qtype)
    {
        // Build and send DNS query for the requested name and qtype
        auto query_bytes = detail::build_dns_query(name, qtype);
        m_socket.send(endpoint{"224.0.0.251", 5353},
                      std::span<const std::byte>(query_bytes));

        std::vector<mdns_record_variant> results;

        // recv_loop is non-copyable/non-movable; construct as local variable
        // using copies of m_socket and m_timer so multiple query() calls work.
        recv_loop<S, T> loop(
            m_socket,                         // copy
            m_timer,                          // copy
            m_silence_timeout,
            // on_packet: walk frame, accumulate parsed records
            [&results](std::span<std::byte> data, endpoint sender)
            {
                detail::walk_dns_frame(
                    std::span<const std::byte>(data.data(), data.size()),
                    sender,
                    [&results](mdns_record_variant rec)
                    {
                        results.push_back(std::move(rec));
                    });
            },
            // on_silence: stop the loop
            [&loop]()
            {
                loop.stop();
            });

        loop.start();
        return results;
    }

private:
    querent(S socket, T timer, std::chrono::milliseconds silence_timeout)
        : m_socket(std::move(socket))
        , m_timer(std::move(timer))
        , m_silence_timeout(silence_timeout)
    {
    }

    S m_socket;
    T m_timer;
    std::chrono::milliseconds m_silence_timeout;
};

} // namespace mdnspp

#endif // HPP_GUARD_MDNSPP_QUERENT_H
