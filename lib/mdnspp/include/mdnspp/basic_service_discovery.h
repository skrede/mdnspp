#ifndef HPP_GUARD_MDNSPP_BASIC_SERVICE_DISCOVERY_H
#define HPP_GUARD_MDNSPP_BASIC_SERVICE_DISCOVERY_H

#include "mdnspp/records.h"
#include "mdnspp/endpoint.h"
#include "mdnspp/service_type.h"
#include "mdnspp/query_options.h"
#include "mdnspp/socket_options.h"
#include "mdnspp/callback_types.h"
#include "mdnspp/resolved_service.h"

#include "mdnspp/detail/compat.h"
#include "mdnspp/detail/dns_wire.h"
#include "mdnspp/detail/basic_mdns_peer_base.h"

#include <span>
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

// basic_service_discovery<P> -- one-shot DNS-SD service discovery
//
// Operations (mutually exclusive -- exactly ONE per instance lifetime):
//   - async_discover():        raw record collection for a service type
//   - async_browse():          aggregated resolved_service collection
//   - async_enumerate_types(): DNS-SD meta-query (RFC 6763 section 9)
//
// Starting a second operation (concurrently or after the first) completes the
// supplied handler with std::errc::operation_in_progress; starting after
// stop() completes with std::errc::invalid_argument. The buffers backing
// results() and services() are therefore never shared between concurrent
// operations.
//
// Completion semantics:
//   - Natural completion (silence_timeout elapsed): error_code{} (success).
//   - stop() before natural completion: std::errc::operation_canceled with the
//     partial results/services accumulated so far.
//   - Destruction with a pending operation: the completion handler is invoked
//     with std::errc::operation_canceled before teardown.
//
// Multicast (QM) queries are delayed by a random interval in
// [response_delay_min, response_delay_max] per RFC 6762 section 5.2; QU
// queries are sent immediately.

template <policy_like P>
class basic_service_discovery : detail::basic_mdns_peer_base<P>
{
    using base = detail::basic_mdns_peer_base<P>;

public:
    using typename base::executor_type;
    using typename base::socket_type;
    using typename base::timer_type;
    using base::socket;
    using base::timer;

    /// Optional callback invoked per record as results arrive during discovery.
    using record_callback = mdnspp::record_callback;

    /// Completion callback fired once when the silence timeout expires
    /// (success) or stop() is called (operation_canceled).
    using completion_handler = mdnspp::discovery_completion_handler;

    /// Completion callback for async_browse.
    using browse_handler = mdnspp::browse_completion_handler;

    /// Completion callback for async_enumerate_types.
    using enumerate_handler = move_only_function<void(std::error_code, std::vector<service_type_info>)>;

    /// Error handler invoked on fire-and-forget send failures.
    using error_handler = mdnspp::error_handler;

    // Non-copyable and non-movable (recv_loop and timer handlers capture this)
    basic_service_discovery(const basic_service_discovery &) = delete;
    basic_service_discovery &operator=(const basic_service_discovery &) = delete;
    basic_service_discovery(basic_service_discovery &&) = delete;
    basic_service_discovery &operator=(basic_service_discovery &&) = delete;

    ~basic_service_discovery()
    {
        this->m_alive.reset();
        stop();
        // The posted stop() teardown is dropped by the expired alive guard;
        // complete a still-pending handler with operation_canceled instead of
        // silently dropping it.
        complete_pending(std::make_error_code(std::errc::operation_canceled));
    }

    // Throwing constructor -- constructs socket and timer from executor.
    // query_options bundles the silence timeout and per-record callback.
    // Throws std::system_error(std::errc::invalid_argument) on invalid options.
    explicit basic_service_discovery(executor_type ex,
                                     query_options opts = {},
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
    basic_service_discovery(executor_type ex,
                            query_options opts,
                            policy_socket_options_t<P> sock_opts,
                            mdns_options mdns_opts,
                            std::error_code &ec)
        : base(ex, std::move(sock_opts), std::move(mdns_opts), ec)
        , m_silence_timeout(opts.silence_timeout)
        , m_delay_timer(ex)
        , m_on_error(std::move(opts.on_error))
        , m_on_record(std::move(opts.on_record))
    {
        if(!ec)
            ec = validate();
    }

    // Accessors for the delay timer (used by the RFC 6762 section 5.2 first-query delay).
    const timer_type &delay_timer() const noexcept { return m_delay_timer; }
    timer_type &delay_timer() noexcept { return m_delay_timer; }

    // Plain callback overloads -- used by default_policy, mock_policy, and ASIO adapter users.
    // When mode is response_mode::unicast the QU bit (RFC 6762 section 5.4) is set,
    // requesting a direct unicast response from the responder instead of a multicast reply.
    void async_discover(std::string_view service_type, completion_handler on_done,
                        response_mode mode = response_mode::multicast)
    {
        auto misuse = check_start_misuse();
        if(!misuse && !dns_name::parse(service_type).has_value())
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
        m_op = op_kind::discover;
        if(on_done)
            m_on_completion = std::move(on_done);
        do_query(std::string(service_type), mode, [this]()
        {
            this->m_loop->stop();
            m_delay_timer.cancel();
            if(auto h = std::exchange(m_on_completion, nullptr); h)
                h(std::error_code{}, m_results);
        });
    }

    /// Aggregating browse -- delivers resolved_service values via RFC 6763 name-chain
    /// correlation (PTR -> SRV -> TXT -> A/AAAA) at the silence timeout.
    /// Completion signature: void(std::error_code, std::vector<resolved_service>).
    /// When mode is response_mode::unicast the QU bit (RFC 6762 section 5.4) is set.
    void async_browse(std::string_view service_type,
                      browse_handler on_done,
                      response_mode mode = response_mode::multicast)
    {
        auto misuse = check_start_misuse();
        if(!misuse && !dns_name::parse(service_type).has_value())
            misuse = make_error_code(mdns_error::invalid_name);
        if(misuse)
        {
            if(on_done)
                this->post_guarded([h = std::move(on_done), misuse]() mutable
                {
                    h(misuse, std::vector<resolved_service>{});
                });
            return;
        }
        m_op = op_kind::browse;
        if(on_done)
            m_on_browse_completion = std::move(on_done);
        do_query(std::string(service_type), mode, [this]()
        {
            this->m_loop->stop();
            m_delay_timer.cancel();
            m_services = mdnspp::aggregate(m_results);
            if(auto h = std::exchange(m_on_browse_completion, nullptr); h)
                h(std::error_code{}, m_services);
        });
    }

    /// DNS-SD service type enumeration (RFC 6763 section 9).
    /// Queries _services._dns-sd._udp.local. and returns parsed service_type_info values.
    void async_enumerate_types(enumerate_handler on_done,
                               response_mode mode = response_mode::multicast)
    {
        if(auto misuse = check_start_misuse())
        {
            if(on_done)
                this->post_guarded([h = std::move(on_done), misuse]() mutable
                {
                    h(misuse, std::vector<service_type_info>{});
                });
            return;
        }
        m_op = op_kind::enumerate;
        if(on_done)
            m_on_enumerate_completion = std::move(on_done);
        do_enumerate(mode);
    }

    /// Subtype-filtered discovery (RFC 6763 section 7.1).
    /// Constructs subtype query name and delegates to async_discover.
    void async_discover_subtype(std::string_view service_type,
                                std::string_view subtype_label,
                                completion_handler on_done,
                                response_mode mode = response_mode::multicast)
    {
        auto query_name = std::string(subtype_label) + "._sub." + std::string(service_type);
        async_discover(query_name, std::move(on_done), mode);
    }

    // Access accumulated raw record results (populated during io.run()).
    // Remains valid after completion -- the completion handler receives a copy.
    //
    // Thread safety: the buffer is mutated on the executor thread while the
    // operation is in flight. Read it only after completion or from the
    // executor thread.
    const std::vector<mdns_record_variant> &results() const noexcept
    {
        return m_results;
    }

    // Access aggregated resolved_service values produced by async_browse.
    // Populated at silence timeout (or stop()) -- empty until browse completes.
    // Same thread-safety contract as results().
    const std::vector<resolved_service> &services() const noexcept
    {
        return m_services;
    }

    // Early termination -- posts teardown to executor thread, ensuring all
    // state mutations happen on the executor (no cross-thread data race).
    // The pending completion handler fires with operation_canceled and the
    // partial results accumulated so far (browse results are aggregated).
    void stop()
    {
        base::stop([this]()
        {
            m_delay_timer.cancel();
            if(this->m_loop)
                this->m_loop->stop();
            complete_pending(std::make_error_code(std::errc::operation_canceled));
        });
    }

private:
    enum class op_kind : uint8_t
    {
        none,
        discover,
        browse,
        enumerate,
    };

    // Detects misuse: a concurrent second operation or reuse after stop().
    [[nodiscard]] std::error_code check_start_misuse() const noexcept
    {
        if(m_op != op_kind::none)
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

    // Fires whichever completion handler is still pending with ec.
    // Browse delivers the aggregation of the records received so far.
    void complete_pending(std::error_code ec)
    {
        switch(m_op)
        {
        case op_kind::discover:
            if(auto h = std::exchange(m_on_completion, nullptr); h)
                h(ec, m_results);
            break;
        case op_kind::browse:
            if(auto h = std::exchange(m_on_browse_completion, nullptr); h)
            {
                m_services = mdnspp::aggregate(m_results);
                h(ec, m_services);
            }
            break;
        case op_kind::enumerate:
            if(auto h = std::exchange(m_on_enumerate_completion, nullptr); h)
                h(ec, m_enumerated_types);
            break;
        case op_kind::none:
            break;
        }
    }

    // Sends query_bytes immediately for QU mode; otherwise delays by a random
    // interval in [response_delay_min, response_delay_max] (RFC 6762 section 5.2).
    void send_query_packet(std::vector<std::byte> query_bytes, response_mode mode,
                           std::string_view context)
    {
        if(mode == response_mode::unicast)
        {
            std::error_code ec;
            this->m_socket.send(this->multicast_endpoint(),
                                std::span<const std::byte>(query_bytes), ec);
            if(ec && m_on_error)
                m_on_error(ec, context);
            return;
        }

        std::uniform_int_distribution<int32_t> dist(
            static_cast<int32_t>(this->m_mdns_opts.response_delay_min.count()),
            static_cast<int32_t>(this->m_mdns_opts.response_delay_max.count()));
        m_delay_timer.expires_after(std::chrono::milliseconds(dist(m_rng)));
        m_delay_timer.async_wait(
            [this, bytes = std::move(query_bytes), context](std::error_code ec)
            {
                if(ec || this->m_stopped.load(std::memory_order_acquire))
                    return;
                std::error_code send_ec;
                this->m_socket.send(this->multicast_endpoint(),
                                    std::span<const std::byte>(bytes), send_ec);
                if(send_ec && m_on_error)
                    m_on_error(send_ec, context);
            });
    }

    // Shared implementation for async_discover and async_browse.
    // Clears results, sends the PTR query (delayed per section 5.2 for QM),
    // creates the recv_loop with the shared on_packet handler, and starts it.
    void do_query(std::string svc_type, response_mode mode,
                  move_only_function<void()> on_silence_fn)
    {
        m_results.clear();
        m_service_type = dns_name(std::move(svc_type));

        auto query_bytes = detail::build_dns_query(m_service_type, dns_type::ptr,
                                                   std::span<const mdns_record_variant>(m_results), mode);

        this->m_loop = std::make_unique<detail::recv_loop<P>>(
            this->m_socket,
            this->m_timer,
            m_silence_timeout,
            [this](const recv_metadata &meta, std::span<std::byte> data) -> bool
            {
                const endpoint &sender = meta.sender;

                auto cdata = std::span<const std::byte>(data.data(), data.size());

                // Records in query packets (QR=0) are known-answer lists or
                // probe proposals, not answers (RFC 6762 section 7.1, section 8.2).
                if(cdata.size() < 12 || !(detail::read_u16_be(cdata.data() + 2) & 0x8000))
                    return false;

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
                            return r.name == m_service_type;
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
            std::move(on_silence_fn),
            this->m_mdns_opts.receive_ttl_minimum,
            this->m_mdns_opts.unknown_ttl_policy,
            [this](std::error_code ec)
            {
                if(m_on_error)
                    m_on_error(ec, "receive");
            });

        this->m_loop->start();
        send_query_packet(std::move(query_bytes), mode, "query send");
    }

    // Sets up the meta-query for DNS-SD service type enumeration (RFC 6763 section 9).
    // Queries _services._dns-sd._udp.local and accumulates parsed service_type_info values.
    void do_enumerate(response_mode mode = response_mode::multicast)
    {
        m_enumerated_types.clear();

        static constexpr std::string_view meta_name = "_services._dns-sd._udp.local";

        auto query_bytes = detail::build_dns_query(meta_name, dns_type::ptr, mode);

        this->m_loop = std::make_unique<detail::recv_loop<P>>(
            this->m_socket,
            this->m_timer,
            m_silence_timeout,
            [this](const recv_metadata &meta, std::span<std::byte> data) -> bool
            {
                const endpoint &sender = meta.sender;

                auto cdata = std::span<const std::byte>(data.data(), data.size());

                // Only response packets carry answers -- see do_query.
                if(cdata.size() < 12 || !(detail::read_u16_be(cdata.data() + 2) & 0x8000))
                    return false;

                bool found = false;
                detail::walk_dns_frame(cdata, sender,
                    [this, &found](mdns_record_variant rec)
                    {
                        if(auto *ptr = std::get_if<record_ptr>(&rec))
                        {
                            if(ptr->name == "_services._dns-sd._udp.local.")
                            {
                                auto info = parse_service_type(ptr->ptr_name);
                                bool dup = std::any_of(m_enumerated_types.begin(),
                                    m_enumerated_types.end(),
                                    [&](const service_type_info &t)
                                    { return t.service_type == info.service_type; });
                                if(!dup)
                                    m_enumerated_types.push_back(std::move(info));
                                found = true;
                            }
                        }
                    });
                return found;
            },
            [this]()
            {
                this->m_loop->stop();
                m_delay_timer.cancel();
                if(auto h = std::exchange(m_on_enumerate_completion, nullptr); h)
                    h(std::error_code{}, m_enumerated_types);
            },
            this->m_mdns_opts.receive_ttl_minimum,
            this->m_mdns_opts.unknown_ttl_policy,
            [this](std::error_code ec)
            {
                if(m_on_error)
                    m_on_error(ec, "receive");
            });

        this->m_loop->start();
        send_query_packet(std::move(query_bytes), mode, "enumerate send");
    }

    op_kind m_op{op_kind::none};
    std::chrono::milliseconds m_silence_timeout;
    std::mt19937 m_rng{std::random_device{}()};
    timer_type m_delay_timer;
    dns_name m_service_type;
    error_handler m_on_error;
    record_callback m_on_record;
    completion_handler m_on_completion;
    enumerate_handler m_on_enumerate_completion;
    browse_handler m_on_browse_completion;
    std::vector<mdns_record_variant> m_results;
    std::vector<resolved_service> m_services;
    std::vector<service_type_info> m_enumerated_types;
};

}

#endif
