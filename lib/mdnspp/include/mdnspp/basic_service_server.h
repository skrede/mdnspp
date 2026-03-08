#ifndef HPP_GUARD_MDNSPP_BASIC_SERVICE_SERVER_H
#define HPP_GUARD_MDNSPP_BASIC_SERVICE_SERVER_H

#include "mdnspp/records.h"
#include "mdnspp/endpoint.h"
#include "mdnspp/mdns_error.h"
#include "mdnspp/service_info.h"
#include "mdnspp/socket_options.h"
#include "mdnspp/service_options.h"

#include "mdnspp/detail/compat.h"
#include "mdnspp/detail/dns_wire.h"
#include "mdnspp/detail/dns_enums.h"
#include "mdnspp/detail/basic_mdns_peer_base.h"

#include <span>
#include <string>
#include <memory>
#include <random>
#include <chrono>
#include <cstdint>
#include <cassert>
#include <utility>
#include <algorithm>
#include <string_view>
#include <system_error>

namespace mdnspp {

// basic_service_server<P> -- mDNS service responder
//
// Policy-based class template parameterized on:
//   P -- Policy: provides executor_type, socket_type, timer_type
//
// Lifecycle:
//   1. Construct with (ex, info, opts, sock_opts) or non-throwing overload
//   2. async_start(on_ready, on_done) -- begins probe -> announce -> live sequence
//      on_ready fires with error_code{} when live, or probe_conflict on conflict
//      on_done fires with error_code{} when stop() is called
//   3. stop() -- idempotent; cancels probing/announcing, fires on_ready with
//      operation_canceled if not yet live, then fires on_done
//   4. ~basic_service_server() -- calls stop() for RAII safety

template <Policy P>
class basic_service_server : detail::basic_mdns_peer_base<P>
{
    using base = detail::basic_mdns_peer_base<P>;

public:
    using typename base::executor_type;
    using typename base::socket_type;
    using typename base::timer_type;
    using base::socket;

    /// Optional callback invoked when an incoming query is received and parsed.
    /// Parameters: sender endpoint, qtype requested, response mode (unicast or multicast).
    using query_callback = detail::move_only_function<void(const endpoint &sender, dns_type type, response_mode mode)>;

    /// Completion callback fired once when stop() is called or on_ready event occurs.
    /// Receives error_code.
    using completion_handler = detail::move_only_function<void(std::error_code)>;

    /// Error handler invoked on fire-and-forget send failures.
    /// Receives the error_code and a context string identifying the send site.
    using error_handler = detail::move_only_function<void(std::error_code, std::string_view)>;

    // Non-copyable
    basic_service_server(const basic_service_server &) = delete;
    basic_service_server &operator=(const basic_service_server &) = delete;

    // Movable only before async_start() is called (m_loop must be null).
    // Moving a started server is a logic error.
    basic_service_server(basic_service_server &&other) noexcept
        : base(std::move(other))
        , m_response_timer(std::move(other.m_response_timer))
        , m_info(std::move(other.m_info))
        , m_opts(std::move(other.m_opts))
        , m_on_ready(std::move(other.m_on_ready))
        , m_on_completion(std::move(other.m_on_completion))
        , m_on_error(std::move(other.m_on_error))
        , m_rng(std::move(other.m_rng))
        , m_state(other.m_state)
        , m_probe_count(other.m_probe_count)
        , m_announce_count(other.m_announce_count)
        , m_conflict_attempt(other.m_conflict_attempt)
        , m_pending_armed(other.m_pending_armed)
        , m_pending_qtype(other.m_pending_qtype)
        , m_pending_needs_nsec(other.m_pending_needs_nsec)
        , m_pending_suppress_ptr(other.m_pending_suppress_ptr)
        , m_pending_suppress_srv(other.m_pending_suppress_srv)
        , m_pending_suppress_a(other.m_pending_suppress_a)
        , m_pending_suppress_aaaa(other.m_pending_suppress_aaaa)
        , m_pending_suppress_txt(other.m_pending_suppress_txt)
    {
    }

    basic_service_server &operator=(basic_service_server &&other) noexcept
    {
        if(this == &other)
            return *this;
        assert(this->m_loop == nullptr);       // this server must not be started
        assert(other.m_loop == nullptr); // source must not be started
        // Move base members via a placement trick is not possible with private
        // inheritance, so we move each accessible member individually.
        this->m_alive = std::move(other.m_alive);
        this->m_executor = other.m_executor;
        this->m_socket = std::move(other.m_socket);
        this->m_timer = std::move(other.m_timer);
        this->m_loop = std::move(other.m_loop);
        this->m_stopped.store(other.m_stopped.load(std::memory_order_acquire),
                              std::memory_order_release);
        other.m_stopped.store(true, std::memory_order_release);
        m_response_timer = std::move(other.m_response_timer);
        m_info = std::move(other.m_info);
        m_opts = std::move(other.m_opts);
        m_on_ready = std::move(other.m_on_ready);
        m_on_completion = std::move(other.m_on_completion);
        m_on_error = std::move(other.m_on_error);
        m_rng = std::move(other.m_rng);
        m_state = other.m_state;
        m_probe_count = other.m_probe_count;
        m_announce_count = other.m_announce_count;
        m_conflict_attempt = other.m_conflict_attempt;
        m_pending_armed = other.m_pending_armed;
        m_pending_qtype = other.m_pending_qtype;
        m_pending_needs_nsec = other.m_pending_needs_nsec;
        m_pending_suppress_ptr = other.m_pending_suppress_ptr;
        m_pending_suppress_srv = other.m_pending_suppress_srv;
        m_pending_suppress_a = other.m_pending_suppress_a;
        m_pending_suppress_aaaa = other.m_pending_suppress_aaaa;
        m_pending_suppress_txt = other.m_pending_suppress_txt;
        return *this;
    }

    ~basic_service_server()
    {
        this->m_alive.reset(); // invalidate sentinel first
        stop();                // then stop (discards pending work via event loop)
    }

    // Throwing constructor
    explicit basic_service_server(executor_type ex, service_info info,
                                  service_options opts = {},
                                  socket_options sock_opts = {})
        : base(ex, sock_opts)
        , m_response_timer(ex)
        , m_info(std::move(info))
        , m_opts(std::move(opts))
        , m_rng(std::random_device{}())
    {
    }

    // Non-throwing constructor
    basic_service_server(executor_type ex, service_info info,
                         service_options opts, socket_options sock_opts,
                         std::error_code &ec)
        : base(ex, sock_opts, ec)
        , m_response_timer(ex)
        , m_info(std::move(info))
        , m_opts(std::move(opts))
        , m_rng(std::random_device{}())
    {
    }

    // async_start() -- begins the probe -> announce -> live sequence.
    // on_ready fires after probe+announce completes (success) or on conflict.
    // on_done fires when stop() is called.
    // Must only be called once; calling async_start() twice is a logic error.
    void async_start(completion_handler on_ready = {}, completion_handler on_done = {})
    {
        assert(m_state == server_state::idle);
        if(on_ready)
            m_on_ready = std::move(on_ready);
        if(on_done)
            m_on_completion = std::move(on_done);
        do_start();
    }

    /// Sets the error handler invoked on fire-and-forget send failures.
    void on_error(error_handler handler) { m_on_error = std::move(handler); }

    // stop() -- idempotent; posts teardown to the executor thread, ensuring all
    // state mutations happen on the executor (no cross-thread data race).
    //
    // The goodbye send happens on the caller thread (best-effort, before posting)
    // because the destructor invalidates m_alive before stop() runs, and the
    // goodbye must complete before that invalidation.
    void stop()
    {
        if(this->m_stopped.exchange(true, std::memory_order_acq_rel))
            return;

        // Best-effort goodbye on caller thread -- non-throwing via ec overload.
        if(m_opts.send_goodbye &&
           (m_state == server_state::live || m_state == server_state::announcing))
        {
            std::error_code ec;
            auto goodbye = detail::build_dns_response(m_info, dns_type::any, 0);
            if(!goodbye.empty())
                this->m_socket.send(endpoint{"224.0.0.251", 5353},
                              std::as_bytes(std::span(goodbye)), ec);
            if(ec && m_on_error) m_on_error(ec, "goodbye send");
        }

        auto guard = std::weak_ptr<bool>(this->m_alive);
        P::post(this->m_executor, [this, guard]()
        {
            if(!guard.lock()) return;

            if(m_state == server_state::probing || m_state == server_state::announcing)
            {
                if(auto h = std::exchange(m_on_ready, nullptr); h)
                    h(std::make_error_code(std::errc::operation_canceled));
            }

            m_state = server_state::stopped;
            m_pending_armed = false;
            m_response_timer.cancel();

            if(this->m_loop)
                this->m_loop->stop();

            if(auto h = std::exchange(m_on_completion, nullptr); h)
                h(std::error_code{});
        });
    }

    // update_service_info() -- posts a service info replacement to the event loop.
    // After the update executes, an announcement burst is sent with announce_count
    // announcements at announce_interval intervals per RFC 6762 section 8.4.
    // Must only be called on a running server (after async_start(), before stop()).
    // Thread-safe: may be called from any thread.
    void update_service_info(service_info new_info)
    {
        assert(!this->m_stopped.load(std::memory_order_acquire)); // must be running
        auto guard = std::weak_ptr<bool>(this->m_alive);
        P::post(this->m_executor, [this, guard, info = std::move(new_info)]() mutable
        {
            if(!guard.lock()) return;
            if(this->m_stopped.load(std::memory_order_acquire)) return;
            m_info = std::move(info);
            m_announce_count = 0;
            send_update_announce();
        });
    }

    // Server-specific timer accessors:
    // timer() returns the response timer (used for probing/announcing/response delays)
    // recv_timer() returns the base timer (used by recv_loop)
    const timer_type &timer() const noexcept { return m_response_timer; }
    timer_type &timer() noexcept { return m_response_timer; }
    const timer_type &recv_timer() const noexcept { return base::timer(); }
    timer_type &recv_timer() noexcept { return base::timer(); }

private:
    enum class server_state : uint8_t { idle, probing, announcing, live, stopped };

    // Common start body -- creates recv_loop and begins probing.
    void do_start()
    {
        this->m_loop = std::make_unique<recv_loop<P>>(
            this->m_socket,
            this->m_timer,
            std::chrono::hours(24 * 365), // "infinite" silence timeout (run until stop())
            [this](const endpoint &sender, std::span<std::byte> data) -> bool
            {
                on_query(sender, data);
                return true;
            },
            []()
            {
                // no-op on silence
            });

        start_probing();
        this->m_loop->start();
    }

    // Begins the probing sequence: random delay 0-250ms, then 3 probes at 250ms intervals.
    void start_probing()
    {
        m_state = server_state::probing;
        m_probe_count = 0;

        // Random delay 0-250ms before first probe (RFC 6762 section 8.1)
        std::uniform_int_distribution dist(0, 250);
        m_response_timer.expires_after(std::chrono::milliseconds(dist(m_rng)));
        m_response_timer.async_wait([this](std::error_code ec)
        {
            if(ec || m_state != server_state::probing) return;
            if(this->m_stopped.load(std::memory_order_acquire)) return;
            send_probe();
        });
    }

    // Sends a single probe query and schedules the next.
    void send_probe()
    {
        if(m_state != server_state::probing) return;
        if(this->m_stopped.load(std::memory_order_acquire)) return;

        auto probe = detail::build_probe_query(m_info);
        std::error_code ec;
        this->m_socket.send(endpoint{"224.0.0.251", 5353}, std::span<const std::byte>(probe), ec);
        if(ec && m_on_error) m_on_error(ec, "probe send");
        ++m_probe_count;

        if(m_probe_count < 3)
        {
            // Schedule next probe at 250ms
            m_response_timer.expires_after(std::chrono::milliseconds(250));
            m_response_timer.async_wait([this](std::error_code ec)
            {
                if(ec || m_state != server_state::probing) return;
                if(this->m_stopped.load(std::memory_order_acquire)) return;
                send_probe();
            });
        }
        else
        {
            // Wait 250ms after last probe for conflicts, then start announcing
            m_response_timer.expires_after(std::chrono::milliseconds(250));
            m_response_timer.async_wait([this](std::error_code ec)
            {
                if(ec || m_state != server_state::probing) return;
                if(this->m_stopped.load(std::memory_order_acquire)) return;
                start_announcing();
            });
        }
    }

    // Begins the announcement burst after successful probing.
    void start_announcing()
    {
        m_state = server_state::announcing;
        m_announce_count = 0;
        send_announce();
    }

    // Sends one announcement and schedules the next if needed.
    void send_announce()
    {
        if(m_state != server_state::announcing) return;
        if(this->m_stopped.load(std::memory_order_acquire)) return;

        send_announcement();
        ++m_announce_count;

        if(m_announce_count < m_opts.announce_count)
        {
            m_response_timer.expires_after(m_opts.announce_interval);
            m_response_timer.async_wait([this](std::error_code ec)
            {
                if(ec || m_state != server_state::announcing) return;
                if(this->m_stopped.load(std::memory_order_acquire)) return;
                send_announce();
            });
        }
        else
        {
            // Probe+announce complete -- server is live
            m_state = server_state::live;
            if(auto h = std::exchange(m_on_ready, nullptr); h)
                h(std::error_code{});
        }
    }

    // Handles conflict detected during probing.
    void handle_conflict()
    {
        m_response_timer.cancel();

        if(m_opts.on_conflict)
        {
            std::string new_name;
            if(m_opts.on_conflict(m_info.service_name, new_name, m_conflict_attempt))
            {
                m_info.service_name = std::move(new_name);
                ++m_conflict_attempt;
                start_probing();
                return;
            }
        }

        // No callback or callback returned false -- fail
        m_state = server_state::stopped;
        this->m_stopped.store(true, std::memory_order_release);
        if(auto h = std::exchange(m_on_ready, nullptr); h)
            h(mdns_error::probe_conflict);
    }

    // Sends update announcements as a burst (for update_service_info).
    void send_update_announce()
    {
        if(this->m_stopped.load(std::memory_order_acquire)) return;
        if(m_state != server_state::live) return;

        send_announcement();
        ++m_announce_count;

        if(m_announce_count < m_opts.announce_count)
        {
            m_response_timer.expires_after(m_opts.announce_interval);
            m_response_timer.async_wait([this](std::error_code ec)
            {
                if(ec || this->m_stopped.load(std::memory_order_acquire)) return;
                if(m_state != server_state::live) return;
                send_update_announce();
            });
        }
    }

    // Returns true if the wire-encoded DNS name at data[12..name_end) matches
    // any name this server is authoritative for.
    bool query_matches(std::span<const std::byte> data, size_t name_end) const
    {
        auto qname = data.subspan(12, name_end - 12);
        auto match = [&](std::string_view name)
        {
            auto encoded = detail::encode_dns_name(name);
            return std::ranges::equal(qname, std::span<const std::byte>(encoded));
        };
        return match(m_info.service_type)
            || match(m_info.service_name)
            || match(m_info.hostname);
    }

    // Returns true if the wire-encoded DNS name at data[name_start..name_end)
    // matches any name this server is authoritative for.
    bool query_matches_at(std::span<const std::byte> data, size_t name_start, size_t name_end) const
    {
        auto qname = data.subspan(name_start, name_end - name_start);
        auto match = [&](std::string_view name)
        {
            auto encoded = detail::encode_dns_name(name);
            return std::ranges::equal(qname, std::span<const std::byte>(encoded));
        };
        return match(m_info.service_type)
            || match(m_info.service_name)
            || match(m_info.hostname);
    }

    // Returns true if the service_info has a record of the given type.
    bool has_record_type(dns_type qtype) const
    {
        switch(qtype)
        {
        case dns_type::a:    return m_info.address_ipv4.has_value();
        case dns_type::aaaa: return m_info.address_ipv6.has_value();
        case dns_type::ptr:
        case dns_type::srv:
        case dns_type::txt:  return true;
        case dns_type::any:  return true;
        default:             return false;
        }
    }

    // Checks if an incoming DNS response contains records matching our probed names.
    bool response_conflicts(std::span<std::byte> data) const
    {
        bool conflict = false;
        detail::walk_dns_frame(std::span<const std::byte>(data.data(), data.size()),
            endpoint{}, [&](mdns_record_variant rv)
        {
            auto check_name = [&](std::string_view record_name)
            {
                // Strip trailing dot from record_name for comparison if needed.
                // service_name etc. have trailing dots. walk_dns_frame produces names without trailing dot.
                auto strip = [](std::string_view s) -> std::string_view
                {
                    if(!s.empty() && s.back() == '.')
                        return s.substr(0, s.size() - 1);
                    return s;
                };
                auto sn = strip(m_info.service_name);
                auto hn = strip(m_info.hostname);
                if(record_name == sn || record_name == hn)
                    conflict = true;
            };

            std::visit([&](const auto &rec)
            {
                check_name(rec.name);
            }, rv);
        });
        return conflict;
    }

    // Strips trailing dot from a string_view for name comparison.
    static constexpr auto strip_dot(std::string_view s) -> std::string_view
    {
        if(!s.empty() && s.back() == '.')
            return s.substr(0, s.size() - 1);
        return s;
    }

    // Returns the meta-query name for DNS-SD service type enumeration.
    static constexpr std::string_view meta_query_name{"_services._dns-sd._udp.local."};

    // Checks whether a wire-encoded DNS name at data[name_start..name_end) matches
    // the DNS-SD meta-query name (_services._dns-sd._udp.local.).
    bool matches_meta_query(std::span<const std::byte> data, size_t name_start, size_t name_end) const
    {
        auto qname = data.subspan(name_start, name_end - name_start);
        auto encoded = detail::encode_dns_name(meta_query_name);
        return std::ranges::equal(qname, std::span<const std::byte>(encoded));
    }

    // Checks whether a wire-encoded DNS name matches any of the server's subtype query names.
    // Returns the matching subtype label, or empty string_view if no match.
    std::string_view matches_subtype_query(std::span<const std::byte> data, size_t name_start, size_t name_end) const
    {
        auto qname = data.subspan(name_start, name_end - name_start);
        for(const auto &sub : m_info.subtypes)
        {
            auto subtype_name = sub + "._sub." + std::string(strip_dot(m_info.service_type)) + ".";
            auto encoded = detail::encode_dns_name(subtype_name);
            if(std::ranges::equal(qname, std::span<const std::byte>(encoded)))
                return sub;
        }
        return {};
    }

    // Builds a meta-query response: PTR record pointing from _services._dns-sd._udp.local.
    // to the server's service_type.
    std::vector<std::byte> build_meta_query_response() const
    {
        std::vector<std::byte> packet;
        detail::push_u16_be(packet, 0x0000); // id
        detail::push_u16_be(packet, 0x8400); // flags: QR=1, AA=1
        detail::push_u16_be(packet, 0x0000); // qdcount
        detail::push_u16_be(packet, 0x0001); // ancount = 1
        detail::push_u16_be(packet, 0x0000); // nscount
        detail::push_u16_be(packet, 0x0000); // arcount

        auto owner = detail::encode_dns_name(meta_query_name);
        auto rdata = detail::encode_dns_name(m_info.service_type);
        detail::append_dns_rr(packet, owner, dns_type::ptr, 4500, rdata, false);

        return packet;
    }

    // Builds a subtype PTR response: PTR record pointing from subtype query name to service instance.
    std::vector<std::byte> build_subtype_response(std::string_view subtype_label) const
    {
        std::vector<std::byte> packet;
        detail::push_u16_be(packet, 0x0000);
        detail::push_u16_be(packet, 0x8400);
        detail::push_u16_be(packet, 0x0000);
        detail::push_u16_be(packet, 0x0001);
        detail::push_u16_be(packet, 0x0000);
        detail::push_u16_be(packet, 0x0000);

        auto subtype_name = std::string(subtype_label) + "._sub." + std::string(strip_dot(m_info.service_type)) + ".";
        auto owner = detail::encode_dns_name(subtype_name);
        auto rdata = detail::encode_dns_name(m_info.service_name);
        detail::append_dns_rr(packet, owner, dns_type::ptr, 4500, rdata, false);

        return packet;
    }

    // Called by recv_loop on every incoming packet.
    void on_query(const endpoint &sender, std::span<std::byte> data)
    {
        if(this->m_stopped.load(std::memory_order_acquire))
            return;

        // During probing: check for conflicting responses, drop everything
        if(m_state == server_state::probing)
        {
            if(data.size() >= 12)
            {
                uint16_t flags = detail::read_u16_be(data.data() + 2);
                if(flags & 0x8000) // QR=1, this is a response
                {
                    if(response_conflicts(data))
                        handle_conflict();
                }
            }
            return;
        }

        // Drop queries during announcing
        if(m_state != server_state::live)
            return;

        if(data.size() < 12)
            return;

        auto cdata = std::span<const std::byte>(data.data(), data.size());
        const std::byte *buf = data.data();

        uint16_t qdcount = detail::read_u16_be(buf + 4);
        if(qdcount == 0)
            return;

        // Iterate all questions, accumulating matched qtypes and response mode.
        dns_type accumulated_qtype = dns_type::none;
        auto resp_mode = response_mode::unicast; // default; switches to multicast if any non-QU
        bool any_matched = false;
        bool needs_nsec = false;
        bool meta_matched = false;
        std::string matched_subtype;

        size_t offset = 12;
        for(uint16_t i = 0; i < qdcount; ++i)
        {
            size_t name_start = offset;
            if(!detail::skip_dns_name(cdata, offset))
                break;
            size_t name_end = offset;

            if(offset + 4 > data.size())
                break;

            dns_type qtype = static_cast<dns_type>(detail::read_u16_be(buf + offset));
            uint16_t qclass = detail::read_u16_be(buf + offset + 2);
            offset += 4;

            // Check meta-query
            if(m_opts.respond_to_meta_queries && qtype == dns_type::ptr &&
               matches_meta_query(cdata, name_start, name_end))
            {
                meta_matched = true;
                if((qclass & 0x8000) == 0)
                    resp_mode = response_mode::multicast;
                continue;
            }

            // Check subtype query
            if(qtype == dns_type::ptr)
            {
                auto sub = matches_subtype_query(cdata, name_start, name_end);
                if(!sub.empty())
                {
                    matched_subtype = sub;
                    if((qclass & 0x8000) == 0)
                        resp_mode = response_mode::multicast;
                    continue;
                }
            }

            if(!query_matches_at(cdata, name_start, name_end))
                continue;

            // Matched question -- accumulate qtype
            if(!any_matched)
            {
                accumulated_qtype = qtype;
                any_matched = true;
            }
            else if(accumulated_qtype != qtype)
            {
                accumulated_qtype = dns_type::any;
            }

            // Check if this specific type is unmatched (for NSEC)
            if(qtype != dns_type::any && !has_record_type(qtype))
                needs_nsec = true;

            // QU/multicast: if ANY matching question has QU bit cleared, use multicast
            if((qclass & 0x8000) == 0)
                resp_mode = response_mode::multicast;
        }

        if(!any_matched && !meta_matched && matched_subtype.empty())
            return;

        // ---------------------------------------------------------------
        // Known-answer suppression (RFC 6762 section 7.1)
        // Parse the Answer section to find records the querier already knows.
        // ---------------------------------------------------------------
        constexpr uint32_t default_ttl = 4500;
        constexpr uint32_t kas_threshold = default_ttl / 2; // 2250

        bool suppress_ptr = false;
        bool suppress_srv = false;
        bool suppress_a = false;
        bool suppress_aaaa = false;
        bool suppress_txt = false;

        if(m_opts.suppress_known_answers && any_matched)
        {
            uint16_t ancount = detail::read_u16_be(buf + 6);
            for(uint16_t i = 0; i < ancount; ++i)
            {
                auto name_result = detail::read_dns_name(cdata, offset);
                if(!name_result.has_value())
                    break;

                if(!detail::skip_dns_name(cdata, offset))
                    break;

                if(offset + 10 > data.size())
                    break;

                dns_type rtype = static_cast<dns_type>(detail::read_u16_be(buf + offset));
                offset += 2;
                offset += 2; // rclass
                uint32_t ttl = detail::read_u32_be(buf + offset);
                offset += 4;
                uint16_t rdlength = detail::read_u16_be(buf + offset);
                offset += 2;
                offset += rdlength;

                if(offset > data.size())
                    break;

                // Compare the answer name against our authoritative names
                auto sn = strip_dot(m_info.service_name);
                auto st = strip_dot(m_info.service_type);
                auto hn = strip_dot(m_info.hostname);
                const auto &ans_name = *name_result;

                bool name_matches = (ans_name == sn || ans_name == st || ans_name == hn);
                if(name_matches && ttl >= kas_threshold)
                {
                    switch(rtype)
                    {
                    case dns_type::ptr:  suppress_ptr = true; break;
                    case dns_type::srv:  suppress_srv = true; break;
                    case dns_type::a:    suppress_a = true; break;
                    case dns_type::aaaa: suppress_aaaa = true; break;
                    case dns_type::txt:  suppress_txt = true; break;
                    default: break;
                    }
                }
            }
        }

        auto is_all_suppressed = [&]() -> bool
        {
            if(!m_opts.suppress_known_answers)
                return false;
            // Only suppress if at least one record type would actually be sent
            // and ALL of those are suppressed
            bool any_would_send = false;

            bool would_send_ptr = (accumulated_qtype == dns_type::ptr || accumulated_qtype == dns_type::any);
            bool would_send_srv = (accumulated_qtype == dns_type::srv || accumulated_qtype == dns_type::any);
            bool would_send_a = (accumulated_qtype == dns_type::a || accumulated_qtype == dns_type::any) && m_info.address_ipv4.has_value();
            bool would_send_aaaa = (accumulated_qtype == dns_type::aaaa || accumulated_qtype == dns_type::any) && m_info.address_ipv6.has_value();
            bool would_send_txt = (accumulated_qtype == dns_type::txt || accumulated_qtype == dns_type::any);

            if(would_send_ptr) { any_would_send = true; if(!suppress_ptr) return false; }
            if(would_send_srv) { any_would_send = true; if(!suppress_srv) return false; }
            if(would_send_a) { any_would_send = true; if(!suppress_a) return false; }
            if(would_send_aaaa) { any_would_send = true; if(!suppress_aaaa) return false; }
            if(would_send_txt) { any_would_send = true; if(!suppress_txt) return false; }
            return any_would_send;
        };

        if(m_opts.on_query && any_matched)
            m_opts.on_query(sender, accumulated_qtype, resp_mode);

        // Handle meta-query response (separate from normal response)
        if(meta_matched)
        {
            auto meta_response = build_meta_query_response();
            std::error_code ec;
            if(resp_mode == response_mode::unicast)
                this->m_socket.send(sender, std::span<const std::byte>(meta_response), ec);
            else
                this->m_socket.send(endpoint{"224.0.0.251", 5353}, std::span<const std::byte>(meta_response), ec);
            if(ec && m_on_error) m_on_error(ec, "meta-query response send");
        }

        // Handle subtype PTR response (separate from normal response)
        if(!matched_subtype.empty())
        {
            auto sub_response = build_subtype_response(matched_subtype);
            std::error_code ec;
            if(resp_mode == response_mode::unicast)
                this->m_socket.send(sender, std::span<const std::byte>(sub_response), ec);
            else
                this->m_socket.send(endpoint{"224.0.0.251", 5353}, std::span<const std::byte>(sub_response), ec);
            if(ec && m_on_error) m_on_error(ec, "subtype response send");
        }

        if(!any_matched)
            return;

        // If all records are suppressed by known-answer, skip response entirely
        if(is_all_suppressed())
            return;

        // Build the response packet with suppression applied
        auto build_response_packet = [&](dns_type qtype_to_send) -> std::vector<std::byte>
        {
            // For specific type queries, check if that type is suppressed
            if(m_opts.suppress_known_answers && qtype_to_send != dns_type::any)
            {
                switch(qtype_to_send)
                {
                case dns_type::ptr:  if(suppress_ptr) return {}; break;
                case dns_type::srv:  if(suppress_srv) return {}; break;
                case dns_type::a:    if(suppress_a) return {}; break;
                case dns_type::aaaa: if(suppress_aaaa) return {}; break;
                case dns_type::txt:  if(suppress_txt) return {}; break;
                default: break;
                }
            }

            auto response = detail::build_dns_response(m_info, qtype_to_send);

            // Append NSEC for unmatched specific types (not for ANY)
            if(needs_nsec && qtype_to_send != dns_type::any)
            {
                if(response.empty())
                {
                    // Build a minimal response with just NSEC in Additional
                    response.clear();
                    detail::push_u16_be(response, 0x0000); // id
                    detail::push_u16_be(response, 0x8400); // flags
                    detail::push_u16_be(response, 0x0000); // qdcount
                    detail::push_u16_be(response, 0x0000); // ancount
                    detail::push_u16_be(response, 0x0000); // nscount
                    detail::push_u16_be(response, 0x0001); // arcount = 1

                    auto owner_name = detail::encode_dns_name(m_info.hostname);
                    detail::append_nsec_rr(response, owner_name, m_info, 4500);
                }
                else
                {
                    // Append NSEC to Additional section and update arcount
                    auto owner_name = detail::encode_dns_name(m_info.hostname);
                    detail::append_nsec_rr(response, owner_name, m_info, 4500);
                    uint16_t arcount = detail::read_u16_be(response.data() + 10);
                    ++arcount;
                    response[10] = static_cast<std::byte>(static_cast<uint8_t>(arcount >> 8));
                    response[11] = static_cast<std::byte>(static_cast<uint8_t>(arcount & 0xFF));
                }
            }

            return response;
        };

        // Unicast: send immediately, skip aggregation
        if(resp_mode == response_mode::unicast)
        {
            auto response = build_response_packet(accumulated_qtype);
            if(!response.empty())
            {
                std::error_code ec;
                this->m_socket.send(sender, std::span<const std::byte>(response), ec);
                if(ec && m_on_error) m_on_error(ec, "response send");
            }
            return;
        }

        // Multicast with aggregation
        if(!m_pending_armed)
        {
            m_pending_armed = true;
            m_pending_qtype = accumulated_qtype;
            m_pending_needs_nsec = needs_nsec;
            m_pending_suppress_ptr = suppress_ptr;
            m_pending_suppress_srv = suppress_srv;
            m_pending_suppress_a = suppress_a;
            m_pending_suppress_aaaa = suppress_aaaa;
            m_pending_suppress_txt = suppress_txt;

            // RFC 6762 section 6: random delay 20-120ms before responding via multicast
            std::uniform_int_distribution dist(20, 120);
            int delay_ms = dist(m_rng);

            m_response_timer.expires_after(std::chrono::milliseconds(delay_ms));
            m_response_timer.async_wait(
                [this](std::error_code ec)
                {
                    if(ec || this->m_stopped.load(std::memory_order_acquire))
                        return;
                    if(m_state != server_state::live)
                        return;

                    auto qtype = m_pending_qtype;
                    bool nsec_needed = m_pending_needs_nsec;
                    bool s_ptr = m_pending_suppress_ptr;
                    bool s_srv = m_pending_suppress_srv;
                    bool s_a = m_pending_suppress_a;
                    bool s_aaaa = m_pending_suppress_aaaa;
                    bool s_txt = m_pending_suppress_txt;
                    m_pending_armed = false;
                    m_pending_qtype = dns_type::none;
                    m_pending_needs_nsec = false;
                    m_pending_suppress_ptr = false;
                    m_pending_suppress_srv = false;
                    m_pending_suppress_a = false;
                    m_pending_suppress_aaaa = false;
                    m_pending_suppress_txt = false;

                    // Check suppression for specific-type queries
                    if(m_opts.suppress_known_answers && qtype != dns_type::any)
                    {
                        bool suppressed = false;
                        switch(qtype)
                        {
                        case dns_type::ptr:  suppressed = s_ptr; break;
                        case dns_type::srv:  suppressed = s_srv; break;
                        case dns_type::a:    suppressed = s_a; break;
                        case dns_type::aaaa: suppressed = s_aaaa; break;
                        case dns_type::txt:  suppressed = s_txt; break;
                        default: break;
                        }
                        if(suppressed)
                            return;
                    }

                    auto response = detail::build_dns_response(m_info, qtype);

                    // Append NSEC for unmatched specific types
                    if(nsec_needed && qtype != dns_type::any)
                    {
                        if(response.empty())
                        {
                            // Build minimal response with NSEC in Additional
                            detail::push_u16_be(response, 0x0000);
                            detail::push_u16_be(response, 0x8400);
                            detail::push_u16_be(response, 0x0000);
                            detail::push_u16_be(response, 0x0000);
                            detail::push_u16_be(response, 0x0000);
                            detail::push_u16_be(response, 0x0001);

                            auto owner = detail::encode_dns_name(m_info.hostname);
                            detail::append_nsec_rr(response, owner, m_info, 4500);
                        }
                        else
                        {
                            auto owner = detail::encode_dns_name(m_info.hostname);
                            detail::append_nsec_rr(response, owner, m_info, 4500);
                            uint16_t arcount = detail::read_u16_be(response.data() + 10);
                            ++arcount;
                            response[10] = static_cast<std::byte>(static_cast<uint8_t>(arcount >> 8));
                            response[11] = static_cast<std::byte>(static_cast<uint8_t>(arcount & 0xFF));
                        }
                    }

                    if(!response.empty())
                    {
                        std::error_code ec;
                        this->m_socket.send(endpoint{"224.0.0.251", 5353},
                                      std::span<const std::byte>(response), ec);
                        if(ec && m_on_error) m_on_error(ec, "response send");
                    }
                });
        }
        else
        {
            // Merge into pending: if different type, escalate to ANY
            if(m_pending_qtype != accumulated_qtype)
                m_pending_qtype = dns_type::any;
            if(needs_nsec)
                m_pending_needs_nsec = true;
            // Do NOT reset the timer
        }
    }

    // Builds and sends a DNS response to dest for the given qtype.
    void send_response(const endpoint &dest, dns_type qtype)
    {
        auto response = detail::build_dns_response(m_info, qtype);
        if(response.empty())
            return;

        std::error_code ec;
        this->m_socket.send(dest, std::span<const std::byte>(response), ec);
        if(ec && m_on_error) m_on_error(ec, "response send");
    }

    // Sends an unsolicited announcement with all records (PTR, SRV, TXT, A/AAAA)
    // to the multicast group. RFC 6762 section 8.4.
    // When announce_subtypes is true, also sends subtype PTR records.
    void send_announcement()
    {
        auto response = detail::build_dns_response(m_info, dns_type::any);
        if(!response.empty())
        {
            std::error_code ec;
            this->m_socket.send(endpoint{"224.0.0.251", 5353}, std::span<const std::byte>(response), ec);
            if(ec && m_on_error) m_on_error(ec, "announcement send");
        }

        if(m_opts.announce_subtypes)
        {
            for(const auto &sub : m_info.subtypes)
            {
                auto sub_response = build_subtype_response(sub);
                if(!sub_response.empty())
                {
                    std::error_code ec;
                    this->m_socket.send(endpoint{"224.0.0.251", 5353}, std::span<const std::byte>(sub_response), ec);
                    if(ec && m_on_error) m_on_error(ec, "announcement send");
                }
            }
        }
    }

    timer_type m_response_timer;
    service_info m_info;
    service_options m_opts;
    completion_handler m_on_ready;
    completion_handler m_on_completion;
    error_handler m_on_error;
    std::mt19937 m_rng;
    server_state m_state{server_state::idle};
    unsigned m_probe_count{0};
    unsigned m_announce_count{0};
    unsigned m_conflict_attempt{0};
    bool m_pending_armed{false};
    dns_type m_pending_qtype{dns_type::none};
    bool m_pending_needs_nsec{false};
    bool m_pending_suppress_ptr{false};
    bool m_pending_suppress_srv{false};
    bool m_pending_suppress_a{false};
    bool m_pending_suppress_aaaa{false};
    bool m_pending_suppress_txt{false};
};

}

#endif
