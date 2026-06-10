#ifndef HPP_GUARD_MDNSPP_BASIC_QUERIER_H
#define HPP_GUARD_MDNSPP_BASIC_QUERIER_H

#include "mdnspp/records.h"
#include "mdnspp/endpoint.h"
#include "mdnspp/query_options.h"
#include "mdnspp/callback_types.h"
#include "mdnspp/socket_options.h"

#include "mdnspp/detail/compat.h"
#include "mdnspp/detail/dns_wire.h"
#include "mdnspp/detail/dns_enums.h"
#include "mdnspp/detail/basic_mdns_peer_base.h"

#include <chrono>
#include <memory>
#include <random>
#include <string>
#include <vector>
#include <cstdint>
#include <utility>
#include <algorithm>
#include <string_view>
#include <system_error>

namespace mdnspp {

// basic_querier<P> -- one-shot mDNS query
//
// Completion semantics:
//   - Natural completion (silence_timeout elapsed): error_code{} (success) with
//     the accumulated results.
//   - stop() before natural completion: std::errc::operation_canceled with the
//     results accumulated so far.
//   - Destruction with a pending operation: the completion handler is invoked
//     with std::errc::operation_canceled before teardown.
//   - A second async_query() (or async_query() after stop()) completes the
//     supplied handler with std::errc::operation_in_progress /
//     std::errc::invalid_argument; the running operation is unaffected.
//
// basic_querier is one-shot: construct a new instance per query.

template<policy_like P>
class basic_querier : detail::basic_mdns_peer_base<P>
{
    using base = detail::basic_mdns_peer_base<P>;

public:
    using typename base::executor_type;
    using typename base::socket_type;
    using typename base::timer_type;
    using base::socket;
    using base::timer;

    /// Optional callback invoked per record as results arrive during a query.
    using record_callback = mdnspp::record_callback;

    /// Completion callback fired once at the silence timeout (success), on
    /// stop() (operation_canceled), or on misuse (see class comment).
    using completion_handler = mdnspp::querier_completion_handler;

    /// Error handler invoked on fire-and-forget send failures.
    using error_handler = mdnspp::error_handler;

    // Non-copyable and non-movable (recv_loop and timer handlers capture this)
    basic_querier(const basic_querier &) = delete;
    basic_querier &operator=(const basic_querier &) = delete;
    basic_querier(basic_querier &&) = delete;
    basic_querier &operator=(basic_querier &&) = delete;

    ~basic_querier()
    {
        this->m_alive.reset();
        stop();
        // The posted stop() teardown is dropped by the expired alive guard, so a
        // pending completion handler is invoked here -- pending handlers must
        // complete with operation_canceled rather than vanish.
        if(auto h = std::exchange(m_on_completion, nullptr); h)
            h(std::make_error_code(std::errc::operation_canceled), std::move(m_results));
    }

    // Throwing constructor -- constructs socket and timer from executor.
    // query_options bundles the silence timeout and per-record callback.
    // Throws std::system_error(std::errc::invalid_argument) on invalid options.
    explicit basic_querier(executor_type ex, query_options opts = {},
                           policy_socket_options_t<P> sock_opts = {},
                           mdns_options mdns_opts = {})
        : base(ex, std::move(sock_opts), std::move(mdns_opts))
        , m_silence_timeout(opts.silence_timeout)
        , m_delay_timer(ex)
        , m_on_error(std::move(opts.on_error))
        , m_on_record(std::move(opts.on_record))
    {
        detail::throw_on_error(validate());
    }

    // Non-throwing constructor -- ec is last (ASIO convention).
    basic_querier(executor_type ex, query_options opts, policy_socket_options_t<P> sock_opts,
                  mdns_options mdns_opts, std::error_code &ec)
        : base(ex, std::move(sock_opts), std::move(mdns_opts), ec)
        , m_silence_timeout(opts.silence_timeout)
        , m_delay_timer(ex)
        , m_on_error(std::move(opts.on_error))
        , m_on_record(std::move(opts.on_record))
    {
        if(!ec)
            ec = validate();
    }

    // Accessors for the delay timer (querier-specific, not from base).
    const timer_type &delay_timer() const noexcept { return m_delay_timer; }
    timer_type &delay_timer() noexcept { return m_delay_timer; }

    // Plain callback overload -- used by default_policy, mock_policy, and ASIO adapter users.
    // When mode is response_mode::unicast the QU bit (RFC 6762 section 5.4) is set,
    // requesting a direct unicast response from the responder instead of a multicast reply.
    //
    // One-shot: a second call (or a call after stop()) completes on_done with
    // operation_in_progress / invalid_argument without touching the running query.
    void async_query(std::string_view name, dns_type qtype, completion_handler on_done, response_mode mode = response_mode::multicast)
    {
        auto misuse = check_start_misuse();
        if(!misuse && !dns_name::parse(name).has_value())
            misuse = make_error_code(mdns_error::invalid_name);
        if(misuse)
        {
            if(on_done)
                this->post_guarded([h = std::move(on_done), misuse]() mutable
                {
                    h(misuse, std::vector<mdns_record_variant>{});
                });
            return;
        }
        if(on_done)
            m_on_completion = std::move(on_done);
        do_query(std::string(name), qtype, mode);
    }

    // Access accumulated results (populated during io.run()).
    // Remains valid after completion -- the completion handler receives a copy.
    //
    // Thread safety: the buffer is mutated on the executor thread while the
    // query is in flight. Read it only after completion or from the executor
    // thread.
    const std::vector<mdns_record_variant> &results() const noexcept
    {
        return m_results;
    }

    // Early termination -- posts teardown to executor thread, ensuring all
    // state mutations happen on the executor (no cross-thread data race).
    // The completion handler fires with operation_canceled and the results
    // accumulated so far.
    void stop()
    {
        base::stop([this]()
        {
            m_delay_timer.cancel();

            if(this->m_loop)
            {
                this->m_loop->stop();
                if(auto h = std::exchange(m_on_completion, nullptr); h)
                    h(std::make_error_code(std::errc::operation_canceled), m_results);
            }
        });
    }

private:
    // Detects one-shot misuse: a second start or reuse after stop().
    [[nodiscard]] std::error_code check_start_misuse() const noexcept
    {
        if(this->m_loop)
            return std::make_error_code(std::errc::operation_in_progress);
        if(this->m_stopped.load(std::memory_order_acquire))
            return std::make_error_code(std::errc::invalid_argument);
        return {};
    }

    [[nodiscard]] std::error_code validate() const noexcept
    {
        if(m_silence_timeout.count() <= 0)
            return std::make_error_code(std::errc::invalid_argument);
        return detail::validate_mdns_options(this->m_mdns_opts);
    }

    // Common query body -- assumes m_on_completion is already set.
    // Must only be called once per lifetime (m_loop must be null on entry).
    //
    // For QM queries (multicast mode): delays sending by a random interval in
    // [response_delay_min, response_delay_max] per RFC 6762 section 5.2. During
    // the delay window, incoming QM queries with a matching question suppress
    // the outgoing query (section 7.3). For QU queries (unicast mode): sends
    // immediately with no delay.
    void do_query(std::string qname, dns_type qtype, response_mode mode = response_mode::multicast)
    {
        init_query_state(std::move(qname), qtype, mode);
        create_recv_loop();

        if(mode == response_mode::unicast)
            start_unicast_query();
        else
            start_multicast_query();
    }

    void init_query_state(std::string qname, dns_type qtype, response_mode mode)
    {
        m_results.clear();
        m_query_name = dns_name(std::move(qname));
        m_query_type = qtype;
        m_query_mode = mode;
        m_duplicate_seen = false;
        m_query_sent = false;
    }

    void send_query()
    {
        auto query_bytes = detail::build_dns_query(m_query_name, m_query_type, m_query_mode);
        std::error_code ec;
        this->m_socket.send(this->multicast_endpoint(),
            std::span<const std::byte>(query_bytes), ec);
        if(ec && m_on_error)
            m_on_error(ec, "query send");
        m_query_sent = true;
    }

    // Duplicate question suppression (RFC 6762 section 7.3):
    // Only checked before our query has been sent, and only for QM queries.
    // Returns true if a duplicate was detected and our query should be suppressed.
    //
    // Section 7.3 permits suppression only when the observed known-answer
    // section contains nothing we do not also hold. The querier holds no known
    // answers, so only a KA-free query (ancount == 0) may suppress ours.
    bool check_duplicate_question(std::span<const std::byte> cdata) const
    {
        if(m_query_sent || m_query_mode != response_mode::multicast || cdata.size() < 12)
            return false;

        uint16_t flags = detail::read_u16_be(cdata.data() + 2);
        if(flags & 0x8000) // QR=1, not a query
            return false;

        uint16_t ancount = detail::read_u16_be(cdata.data() + 6);
        if(ancount != 0) // carries known answers -- must not suppress (section 7.3)
            return false;

        uint16_t qdcount = detail::read_u16_be(cdata.data() + 4);
        std::size_t offset = 12;

        for(uint16_t i = 0; i < qdcount; ++i)
        {
            std::size_t name_start = offset;
            if(!detail::skip_dns_name(cdata, offset))
                break;
            if(offset + 4 > cdata.size())
                break;

            uint16_t q_type = detail::read_u16_be(cdata.data() + offset);
            offset += 2;
            uint16_t q_class = detail::read_u16_be(cdata.data() + offset);
            offset += 2;

            bool is_qm = (q_class & 0x8000) == 0;
            bool type_match = q_type == detail::to_underlying(m_query_type);

            if(type_match && is_qm)
            {
                auto incoming_name = detail::read_dns_name(cdata, name_start);
                if(incoming_name.has_value() && m_query_name == dns_name{*incoming_name})
                    return true;
            }
        }
        return false;
    }

    // Parses response records and collects those relevant to our query.
    // Returns true if any relevant record was found (resets silence timer).
    //
    // Only response packets (QR=1) contribute results: records in query packets
    // are known-answer lists or probe proposals, not answers (RFC 6762 section 7.1,
    // section 8.2).
    bool process_response_packet(const endpoint &sender, std::span<const std::byte> cdata)
    {
        if(cdata.size() < 12 || !(detail::read_u16_be(cdata.data() + 2) & 0x8000))
            return false;

        std::vector<mdns_record_variant> batch;
        detail::walk_dns_frame(cdata, sender,
            [&batch](mdns_record_variant rec)
            {
                batch.push_back(std::move(rec));
            });

        bool relevant = std::any_of(batch.begin(), batch.end(), [this](const mdns_record_variant &rec)
        {
            return std::visit([this](const auto &r) { return r.name == m_query_name; }, rec);
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
    }

    void fire_completion()
    {
        this->m_loop->stop();
        m_delay_timer.cancel();
        if(auto h = std::exchange(m_on_completion, nullptr); h)
            h(std::error_code{}, m_results);
    }

    void create_recv_loop()
    {
        this->m_loop = std::make_unique<detail::recv_loop<P>>(
            this->m_socket,
            this->m_timer,
            m_silence_timeout,
            [this](const recv_metadata &meta, std::span<std::byte> data) -> bool
            {
                if(this->m_stopped.load(std::memory_order_acquire))
                    return false;

                auto cdata = std::span<const std::byte>(data.data(), data.size());

                if(check_duplicate_question(cdata))
                {
                    m_duplicate_seen = true;
                    m_delay_timer.cancel();
                }

                return process_response_packet(meta.sender, cdata);
            },
            [this]() { fire_completion(); },
            this->m_mdns_opts.receive_ttl_minimum,
            this->m_mdns_opts.unknown_ttl_policy,
            [this](std::error_code ec)
            {
                if(m_on_error)
                    m_on_error(ec, "receive");
            });
    }

    // QU: send immediately, then start recv_loop.
    void start_unicast_query()
    {
        send_query();
        this->m_loop->start();
    }

    // QM: start recv_loop first (to detect duplicates), then delay send.
    void start_multicast_query()
    {
        this->m_loop->start();

        std::uniform_int_distribution<int32_t> dist(
            static_cast<int32_t>(this->m_mdns_opts.response_delay_min.count()),
            static_cast<int32_t>(this->m_mdns_opts.response_delay_max.count()));
        auto delay = std::chrono::milliseconds(dist(m_rng));

        m_delay_timer.expires_after(delay);
        m_delay_timer.async_wait(
            [this](std::error_code ec)
            {
                if(ec)
                    return;
                if(!m_duplicate_seen)
                    send_query();
            });
    }

    // -------------------------------------------------------------------------
    // Data members -- ordered: fundamental types first, then abstract types;
    // within each group: ascending by type length, then name length, then alpha.
    // -------------------------------------------------------------------------

    bool m_duplicate_seen{false};
    bool m_query_sent{false};
    dns_type m_query_type{dns_type::none};
    response_mode m_query_mode{response_mode::multicast};
    std::chrono::milliseconds m_silence_timeout;
    std::mt19937 m_rng{std::random_device{}()};
    timer_type m_delay_timer;
    dns_name m_query_name;
    error_handler m_on_error;
    record_callback m_on_record;
    completion_handler m_on_completion;
    std::vector<mdns_record_variant> m_results;
};

}

#endif
