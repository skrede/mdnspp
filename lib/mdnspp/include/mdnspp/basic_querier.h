#ifndef HPP_GUARD_MDNSPP_BASIC_QUERIER_H
#define HPP_GUARD_MDNSPP_BASIC_QUERIER_H

#include "mdnspp/policy.h"
#include "mdnspp/records.h"
#include "mdnspp/endpoint.h"
#include "mdnspp/socket_options.h"

#include "mdnspp/detail/compat.h"
#include "mdnspp/detail/dns_wire.h"
#include "mdnspp/detail/recv_loop.h"
#include "mdnspp/detail/dns_enums.h"

#include <memory>
#include <random>
#include <string>
#include <vector>
#include <chrono>
#include <cstdint>
#include <cassert>
#include <utility>
#include <algorithm>
#include <string_view>
#include <system_error>

namespace mdnspp {

template <Policy P>
class basic_querier
{
public:
    using executor_type = typename P::executor_type;
    using socket_type = typename P::socket_type;
    using timer_type = typename P::timer_type;

    /// Optional callback invoked per record as results arrive during a query.
    using record_callback = detail::move_only_function<void(const endpoint &, const mdns_record_variant &)>;

    /// Completion callback fired once when the silence timeout expires (or stop() is called).
    /// Receives error_code (always success for normal completion) and the accumulated results.
    using completion_handler = detail::move_only_function<void(std::error_code, std::vector<mdns_record_variant>)>;

    // Non-copyable (owns recv_loop by unique_ptr)
    basic_querier(const basic_querier &) = delete;
    basic_querier &operator=(const basic_querier &) = delete;

    // Movable only before async_query() is called (m_loop must be null).
    basic_querier(basic_querier &&other) noexcept
        : m_socket(std::move(other.m_socket))
        , m_timer(std::move(other.m_timer))
        , m_delay_timer(std::move(other.m_delay_timer))
        , m_silence_timeout(other.m_silence_timeout)
        , m_on_record(std::move(other.m_on_record))
        , m_on_completion(std::move(other.m_on_completion))
        , m_loop(std::move(other.m_loop))
        , m_results(std::move(other.m_results))
        , m_query_type(other.m_query_type)
        , m_query_mode(other.m_query_mode)
        , m_duplicate_seen(other.m_duplicate_seen)
        , m_query_sent(other.m_query_sent)
    {
        assert(other.m_loop == nullptr); // source must not have been started
    }

    basic_querier &operator=(basic_querier &&) = delete;

    ~basic_querier()
    {
        m_loop.reset(); // destroyed before m_socket/m_timer (reverse declaration order)
    }

    // Throwing constructor — constructs socket and timer from executor.
    // Silence timeout determines how long to wait after the last relevant packet
    // before stopping the recv_loop.
    explicit basic_querier(executor_type ex,
                           std::chrono::milliseconds silence_timeout,
                           record_callback on_record = {})
        : m_socket(ex)
        , m_timer(ex)
        , m_delay_timer(ex)
        , m_silence_timeout(silence_timeout)
        , m_on_record(std::move(on_record))
        , m_loop(nullptr)
    {
    }

    // Non-throwing constructors — ec is last (ASIO convention).
    basic_querier(executor_type ex,
                  std::chrono::milliseconds silence_timeout,
                  record_callback on_record,
                  std::error_code &ec)
        : m_socket(ex, ec)
        , m_timer(ex)
        , m_delay_timer(ex)
        , m_silence_timeout(silence_timeout)
        , m_on_record(std::move(on_record))
        , m_loop(nullptr)
    {
    }

    basic_querier(executor_type ex,
                  std::chrono::milliseconds silence_timeout,
                  std::error_code &ec)
        : m_socket(ex, ec)
        , m_timer(ex)
        , m_delay_timer(ex)
        , m_silence_timeout(silence_timeout)
        , m_loop(nullptr)
    {
    }

    // Throwing constructor with socket_options.
    explicit basic_querier(executor_type ex, const socket_options &opts,
                           std::chrono::milliseconds silence_timeout,
                           record_callback on_record = {})
        : m_socket(ex, opts)
        , m_timer(ex)
        , m_delay_timer(ex)
        , m_silence_timeout(silence_timeout)
        , m_on_record(std::move(on_record))
        , m_loop(nullptr)
    {
    }

    // Non-throwing constructors with socket_options.
    basic_querier(executor_type ex, const socket_options &opts,
                  std::chrono::milliseconds silence_timeout,
                  record_callback on_record, std::error_code &ec)
        : m_socket(ex, opts, ec)
        , m_timer(ex)
        , m_delay_timer(ex)
        , m_silence_timeout(silence_timeout)
        , m_on_record(std::move(on_record))
        , m_loop(nullptr)
    {
    }

    basic_querier(executor_type ex, const socket_options &opts,
                  std::chrono::milliseconds silence_timeout,
                  std::error_code &ec)
        : m_socket(ex, opts, ec)
        , m_timer(ex)
        , m_delay_timer(ex)
        , m_silence_timeout(silence_timeout)
        , m_loop(nullptr)
    {
    }

    // Accessors — basic_querier owns socket and timer directly.
    const socket_type &socket() const noexcept { return m_socket; }
    socket_type &socket() noexcept { return m_socket; }
    const timer_type &timer() const noexcept { return m_timer; }
    timer_type &timer() noexcept { return m_timer; }
    const timer_type &delay_timer() const noexcept { return m_delay_timer; }
    timer_type &delay_timer() noexcept { return m_delay_timer; }

    // Plain callback overload — used by NativePolicy, MockPolicy, and ASIO adapter users.
    // When mode is response_mode::unicast the QU bit (RFC 6762 §5.4) is set,
    // requesting a direct unicast response from the responder instead of a multicast reply.
    void async_query(std::string_view name, dns_type qtype, completion_handler on_done,
                     response_mode mode = response_mode::multicast)
    {
        assert(m_loop == nullptr); // one query per lifetime
        if(on_done)
            m_on_completion = std::move(on_done);
        do_query(std::string(name), qtype, mode);
    }

    // Access accumulated results (populated during io.run()).
    // Remains valid after completion — the completion handler receives a copy.
    const std::vector<mdns_record_variant> &results() const noexcept
    {
        return m_results;
    }

    // Early termination — stops the recv_loop and fires the completion handler.
    void stop()
    {
        m_delay_timer.cancel();
        if(m_loop)
        {
            m_loop->stop();
            if(auto h = std::exchange(m_on_completion, nullptr); h)
                h(std::error_code{}, m_results);
        }
    }

private:
    // Common query body — assumes m_on_completion is already set.
    // Sets up m_query_name, sends DNS query, creates and starts recv_loop.
    // Must only be called once per lifetime (m_loop must be null on entry).
    //
    // For QM queries (multicast mode): delays sending by 20-120ms random interval
    // per RFC 6762 section 5.2. During the delay window, incoming QM queries with
    // a matching question suppress the outgoing query (section 7.3).
    // For QU queries (unicast mode): sends immediately with no delay.
    void do_query(std::string qname, dns_type qtype,
                  response_mode mode = response_mode::multicast)
    {
        assert(m_loop == nullptr); // one query per lifetime
        m_results.clear();
        m_query_name = std::move(qname);
        m_query_type = qtype;
        m_query_mode = mode;
        m_duplicate_seen = false;
        m_query_sent = false;
        // Strip trailing dot so the name matches read_dns_name output (no trailing dot)
        if(!m_query_name.empty() && m_query_name.back() == '.')
            m_query_name.pop_back();

        auto send_query = [this]()
        {
            auto query_bytes = detail::build_dns_query(m_query_name, m_query_type, m_query_mode);
            m_socket.send(endpoint{"224.0.0.251", 5353},
                          std::span<const std::byte>(query_bytes));
            m_query_sent = true;
        };

        // Cache the encoded query name for duplicate detection
        m_encoded_query_name = detail::encode_dns_name(m_query_name);

        m_loop = std::make_unique<recv_loop<P>>(
            m_socket,
            m_timer,
            m_silence_timeout,
            // on_packet: check for duplicate queries during delay, then walk frame
            [this](const endpoint &sender, std::span<std::byte> data) -> bool
            {
                auto cdata = std::span<const std::byte>(data.data(), data.size());

                // Duplicate question suppression (RFC 6762 section 7.3):
                // Only check before our query has been sent, and only for QM queries.
                if(!m_query_sent && m_query_mode == response_mode::multicast && cdata.size() >= 12)
                {
                    uint16_t flags = detail::read_u16_be(cdata.data() + 2);
                    bool is_query = (flags & 0x8000) == 0; // QR=0

                    if(is_query)
                    {
                        uint16_t qdcount = detail::read_u16_be(cdata.data() + 4);
                        size_t offset = 12;

                        for(uint16_t i = 0; i < qdcount; ++i)
                        {
                            size_t name_start = offset;
                            if(!detail::skip_dns_name(cdata, offset))
                                break;
                            if(offset + 4 > cdata.size())
                                break;

                            uint16_t q_type = detail::read_u16_be(cdata.data() + offset);
                            offset += 2;
                            uint16_t q_class = detail::read_u16_be(cdata.data() + offset);
                            offset += 2;

                            bool is_qm = (q_class & 0x8000) == 0; // QU bit not set
                            bool type_match = q_type == std::to_underlying(m_query_type);

                            if(type_match && is_qm)
                            {
                                // Compare encoded name
                                auto incoming_name = detail::read_dns_name(cdata, name_start);
                                if(incoming_name.has_value() && *incoming_name == m_query_name)
                                {
                                    m_duplicate_seen = true;
                                    m_delay_timer.cancel();
                                    break;
                                }
                            }
                        }
                    }
                }

                // Normal response processing
                std::vector<mdns_record_variant> batch;
                detail::walk_dns_frame(cdata, sender,
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

                if(relevant)
                {
                    if(m_on_record)
                    {
                        for(const auto &rec : batch)
                            m_on_record(sender, rec);
                    }
                    m_results.insert(m_results.end(),
                                     std::make_move_iterator(batch.begin()),
                                     std::make_move_iterator(batch.end()));
                }
                return relevant;
            },
            // on_silence: stop the loop and fire the completion handler with results
            [this]()
            {
                m_loop->stop();
                if(auto h = std::exchange(m_on_completion, nullptr); h)
                    h(std::error_code{}, m_results);
            });

        if(mode == response_mode::unicast)
        {
            // QU: send immediately, then start recv_loop
            send_query();
            m_loop->start();
        }
        else
        {
            // QM: start recv_loop first (to detect duplicates), then delay send
            m_loop->start();

            std::mt19937 rng(std::random_device{}());
            std::uniform_int_distribution<int> dist(20, 120);
            auto delay = std::chrono::milliseconds(dist(rng));

            m_delay_timer.expires_after(delay);
            m_delay_timer.async_wait(
                [this, send_query](std::error_code ec)
                {
                    if(ec)
                        return; // cancelled (duplicate seen or stopped)
                    if(!m_duplicate_seen)
                        send_query();
                });
        }
    }

    socket_type m_socket;
    timer_type m_timer;
    timer_type m_delay_timer;
    std::chrono::milliseconds m_silence_timeout;
    record_callback m_on_record;
    completion_handler m_on_completion;
    std::string m_query_name;
    std::unique_ptr<recv_loop<P>> m_loop;
    std::vector<mdns_record_variant> m_results;
    dns_type m_query_type{dns_type::none};
    response_mode m_query_mode{response_mode::multicast};
    bool m_duplicate_seen{false};
    bool m_query_sent{false};
    std::vector<std::byte> m_encoded_query_name;
};

}

#endif
