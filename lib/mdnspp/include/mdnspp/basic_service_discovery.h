#ifndef HPP_GUARD_MDNSPP_BASIC_SERVICE_DISCOVERY_H
#define HPP_GUARD_MDNSPP_BASIC_SERVICE_DISCOVERY_H

#include "mdnspp/records.h"
#include "mdnspp/endpoint.h"
#include "mdnspp/service_type.h"
#include "mdnspp/socket_options.h"
#include "mdnspp/resolved_service.h"

#include "mdnspp/detail/compat.h"
#include "mdnspp/detail/dns_wire.h"
#include "mdnspp/detail/basic_mdns_peer_base.h"

#include <span>
#include <chrono>
#include <memory>
#include <string>
#include <vector>
#include <cassert>
#include <utility>
#include <algorithm>
#include <string_view>
#include <system_error>

namespace mdnspp {

template <Policy P>
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
    using record_callback = detail::move_only_function<void(const endpoint &, const mdns_record_variant &)>;

    /// Completion callback fired once when the silence timeout expires (or stop() is called).
    /// Receives error_code (always success for normal completion) and the accumulated results.
    using completion_handler = detail::move_only_function<void(std::error_code, const std::vector<mdns_record_variant> &)>;

    /// Completion callback for async_enumerate_types.
    using enumerate_handler = detail::move_only_function<void(std::error_code, std::vector<service_type_info>)>;

    /// Error handler invoked on fire-and-forget send failures.
    using error_handler = detail::move_only_function<void(std::error_code, std::string_view)>;

    // Non-copyable (owns recv_loop by unique_ptr)
    basic_service_discovery(const basic_service_discovery &) = delete;
    basic_service_discovery &operator=(const basic_service_discovery &) = delete;
    basic_service_discovery &operator=(basic_service_discovery &&) = delete;

    // Movable only before async_discover()/async_browse() is called (loops must be null).
    basic_service_discovery(basic_service_discovery &&other) noexcept
        : base(std::move(other))
        , m_silence_timeout(other.m_silence_timeout)
        , m_on_record(std::move(other.m_on_record))
        , m_on_completion(std::move(other.m_on_completion))
        , m_on_browse_completion(std::move(other.m_on_browse_completion))
        , m_on_enumerate_completion(std::move(other.m_on_enumerate_completion))
        , m_on_error(std::move(other.m_on_error))
        , m_browse_loop(std::move(other.m_browse_loop))
        , m_enumerate_loop(std::move(other.m_enumerate_loop))
        , m_results(std::move(other.m_results))
        , m_services(std::move(other.m_services))
        , m_enumerated_types(std::move(other.m_enumerated_types))
    {
        assert(other.m_browse_loop == nullptr);
        assert(other.m_enumerate_loop == nullptr);
    }

    ~basic_service_discovery()
    {
        this->m_alive.reset();
        stop();
    }

    // Throwing constructor -- constructs socket and timer from executor.
    // Silence timeout determines how long to wait after the last relevant packet
    // before stopping the recv_loop.
    explicit basic_service_discovery(executor_type ex,
                                     std::chrono::milliseconds silence_timeout,
                                     socket_options opts = {},
                                     record_callback on_record = {})
        : base(ex, opts)
        , m_silence_timeout(silence_timeout)
        , m_on_record(std::move(on_record))
    {
    }

    // Non-throwing constructor -- ec is last (ASIO convention).
    basic_service_discovery(executor_type ex,
                            std::chrono::milliseconds silence_timeout,
                            socket_options opts,
                            record_callback on_record,
                            std::error_code &ec)
        : base(ex, opts, ec)
        , m_silence_timeout(silence_timeout)
        , m_on_record(std::move(on_record))
    {
    }

    // Plain callback overloads -- used by NativePolicy, MockPolicy, and ASIO adapter users.
    // When mode is response_mode::unicast the QU bit (RFC 6762 section 5.4) is set,
    // requesting a direct unicast response from the responder instead of a multicast reply.
    void async_discover(std::string_view service_type, completion_handler on_done,
                        response_mode mode = response_mode::multicast)
    {
        assert(this->m_loop == nullptr); // one discover per lifetime
        if(on_done)
            m_on_completion = std::move(on_done);
        do_discover(std::string(service_type), mode);
    }

    /// Aggregating browse -- delivers resolved_service values via RFC 6763 name-chain
    /// correlation (PTR -> SRV -> TXT -> A/AAAA) at the silence timeout.
    /// Completion signature: void(std::error_code, std::vector<resolved_service>).
    /// When mode is response_mode::unicast the QU bit (RFC 6762 section 5.4) is set.
    void async_browse(std::string_view service_type,
                      detail::move_only_function<void(std::error_code, std::vector<resolved_service>)> on_done,
                      response_mode mode = response_mode::multicast)
    {
        assert(m_browse_loop == nullptr); // one browse per lifetime
        if(on_done)
            m_on_browse_completion = std::move(on_done);
        do_browse(std::string(service_type), mode);
    }

    /// DNS-SD service type enumeration (RFC 6763 section 9).
    /// Queries _services._dns-sd._udp.local. and returns parsed service_type_info values.
    void async_enumerate_types(enumerate_handler on_done,
                               response_mode mode = response_mode::multicast)
    {
        assert(m_enumerate_loop == nullptr); // one enumerate per lifetime
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
    const std::vector<mdns_record_variant> &results() const noexcept
    {
        return m_results;
    }

    // Access aggregated resolved_service values produced by async_browse.
    // Populated at silence timeout (or stop()) -- empty until browse completes.
    const std::vector<resolved_service> &services() const noexcept
    {
        return m_services;
    }

    /// Sets the error handler invoked on fire-and-forget send failures.
    void on_error(error_handler handler) { m_on_error = std::move(handler); }

    // Early termination -- posts teardown to executor thread, ensuring all
    // state mutations happen on the executor (no cross-thread data race).
    void stop()
    {
        base::stop([this]()
        {
            if(this->m_loop)
            {
                this->m_loop->stop();
                if(auto h = std::exchange(m_on_completion, nullptr); h)
                    h(std::error_code{}, m_results);
            }
            if(m_browse_loop)
            {
                m_browse_loop->stop();
                m_services = mdnspp::aggregate(m_results);
                if(auto h = std::exchange(m_on_browse_completion, nullptr); h)
                    h(std::error_code{}, m_services);
            }
            if(m_enumerate_loop)
            {
                m_enumerate_loop->stop();
                if(auto h = std::exchange(m_on_enumerate_completion, nullptr); h)
                    h(std::error_code{}, m_enumerated_types);
            }
        });
    }

private:
    // Common browse body -- assumes m_on_browse_completion is already set.
    // Mirrors do_discover() exactly; silence callback calls aggregate(m_results)
    // instead of firing the discover handler.
    // Must only be called once per lifetime (m_browse_loop must be null on entry).
    void do_browse(std::string svc_type, response_mode mode = response_mode::multicast)
    {
        assert(m_browse_loop == nullptr); // one browse per lifetime
        m_results.clear();
        m_service_type = std::move(svc_type);
        if(!m_service_type.empty() && m_service_type.back() == '.')
            m_service_type.pop_back();

        // Build and send DNS PTR query (qtype = 12) -- same as do_discover()
        // Includes known answers (m_results) per RFC 6762 section 7.1
        auto query_bytes = detail::build_dns_query(m_service_type, dns_type::ptr,
                                                   std::span<const mdns_record_variant>(m_results), mode);
        {
            std::error_code ec;
            this->m_socket.send(endpoint{"224.0.0.251", 5353},
                          std::span<const std::byte>(query_bytes), ec);
            if(ec && m_on_error) m_on_error(ec, "browse send");
        }

        m_browse_loop = std::make_unique<recv_loop<P>>(
            this->m_socket,
            this->m_timer,
            m_silence_timeout,
            // on_packet: identical to do_discover() -- accumulates into m_results,
            // fires m_on_record per relevant record.
            [this](const endpoint &sender, std::span<std::byte> data) -> bool
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
            // on_silence: aggregate raw records into resolved_service values, fire handler
            [this]()
            {
                m_browse_loop->stop();
                m_services = mdnspp::aggregate(m_results);
                if(auto h = std::exchange(m_on_browse_completion, nullptr); h)
                    h(std::error_code{}, m_services);
            });

        m_browse_loop->start();
    }

    // Sets up m_service_type, sends DNS query, creates and starts recv_loop.
    // Must only be called once per lifetime (m_loop must be null on entry).
    void do_discover(std::string svc_type, response_mode mode = response_mode::multicast)
    {
        assert(this->m_loop == nullptr); // one discover per lifetime
        m_results.clear();
        m_service_type = std::move(svc_type);
        // Strip trailing dot so the name matches read_dns_name output (no trailing dot)
        if(!m_service_type.empty() && m_service_type.back() == '.')
            m_service_type.pop_back();

        // Build and send DNS PTR query (qtype = 12)
        // Includes known answers (m_results) per RFC 6762 section 7.1
        auto query_bytes = detail::build_dns_query(m_service_type, dns_type::ptr,
                                                   std::span<const mdns_record_variant>(m_results), mode);
        {
            std::error_code ec;
            this->m_socket.send(endpoint{"224.0.0.251", 5353},
                          std::span<const std::byte>(query_bytes), ec);
            if(ec && m_on_error) m_on_error(ec, "discover send");
        }

        this->m_loop = std::make_unique<recv_loop<P>>(
            this->m_socket,
            this->m_timer,
            m_silence_timeout,
            // on_packet: walk frame into temp, keep all records from packets
            // that contain at least one record matching the queried service type.
            // Returns true (reset timer) only for relevant packets.
            [this](const endpoint &sender, std::span<std::byte> data) -> bool
            {
                std::vector<mdns_record_variant> batch;
                detail::walk_dns_frame(
                    std::span<const std::byte>(data.data(), data.size()),
                    sender,
                    [&batch](mdns_record_variant rec)
                    {
                        batch.push_back(std::move(rec));
                    });

                bool relevant = std::any_of(
                    batch.begin(), batch.end(),
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
            // on_silence: stop the loop and fire the completion handler with results
            [this]()
            {
                this->m_loop->stop();
                if(auto h = std::exchange(m_on_completion, nullptr); h)
                    h(std::error_code{}, m_results);
            });

        this->m_loop->start();
    }

    // Sets up the meta-query for DNS-SD service type enumeration (RFC 6763 section 9).
    // Queries _services._dns-sd._udp.local and accumulates parsed service_type_info values.
    void do_enumerate(response_mode mode = response_mode::multicast)
    {
        assert(m_enumerate_loop == nullptr);
        m_enumerated_types.clear();

        static constexpr std::string_view meta_name = "_services._dns-sd._udp.local";

        auto query_bytes = detail::build_dns_query(meta_name, dns_type::ptr, mode);
        {
            std::error_code ec;
            this->m_socket.send(endpoint{"224.0.0.251", 5353},
                          std::span<const std::byte>(query_bytes), ec);
            if(ec && m_on_error) m_on_error(ec, "enumerate send");
        }

        m_enumerate_loop = std::make_unique<recv_loop<P>>(
            this->m_socket,
            this->m_timer,
            m_silence_timeout,
            [this](const endpoint &sender, std::span<std::byte> data) -> bool
            {
                bool found = false;
                detail::walk_dns_frame(
                    std::span<const std::byte>(data.data(), data.size()),
                    sender,
                    [this, &found](mdns_record_variant rec)
                    {
                        if(auto *ptr = std::get_if<record_ptr>(&rec))
                        {
                            if(ptr->name == "_services._dns-sd._udp.local")
                            {
                                m_enumerated_types.push_back(
                                    parse_service_type(ptr->ptr_name));
                                found = true;
                            }
                        }
                    });
                return found;
            },
            [this]()
            {
                m_enumerate_loop->stop();
                if(auto h = std::exchange(m_on_enumerate_completion, nullptr); h)
                    h(std::error_code{}, m_enumerated_types);
            });

        m_enumerate_loop->start();
    }

    std::chrono::milliseconds m_silence_timeout;
    record_callback m_on_record;
    completion_handler m_on_completion;
    detail::move_only_function<void(std::error_code, std::vector<resolved_service>)> m_on_browse_completion;
    enumerate_handler m_on_enumerate_completion;
    error_handler m_on_error;
    std::string m_service_type;
    std::unique_ptr<recv_loop<P>> m_browse_loop;
    std::unique_ptr<recv_loop<P>> m_enumerate_loop;
    std::vector<mdns_record_variant> m_results;
    std::vector<resolved_service> m_services;
    std::vector<service_type_info> m_enumerated_types;
};

}

#endif
