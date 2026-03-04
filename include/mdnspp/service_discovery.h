#ifndef HPP_GUARD_MDNSPP_SERVICE_DISCOVERY_H
#define HPP_GUARD_MDNSPP_SERVICE_DISCOVERY_H

#include "mdnspp/policy.h"
#include "mdnspp/records.h"
#include "mdnspp/endpoint.h"
#include "mdnspp/resolved_service.h"

#include <algorithm>
#include <functional>
#include <memory>
#include <string>
#include <vector>
#include <chrono>
#include <string_view>
#include <cassert>
#include <system_error>
#include <utility>

// These private headers are available via the src/ include directory
// (added as PRIVATE to each test target in CMakeLists.txt)
#include "mdnspp/recv_loop.h"
#include "mdnspp/dns_wire.h"

#ifdef ASIO_STANDALONE
#include <asio/async_result.hpp>
#include <asio/dispatch.hpp>
#include <asio/executor_work_guard.hpp>
#include <asio/bind_allocator.hpp>
#include <asio/recycling_allocator.hpp>
#include <asio/associated_allocator.hpp>
#endif

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

    /// Completion callback fired once when the silence timeout expires (or stop() is called).
    /// Receives error_code (always success for normal completion) and the accumulated results.
    using completion_handler = std::function<void(std::error_code, std::vector<mdns_record_variant>)>;

    /// Completion callback for async_browse — delivers aggregated resolved_service values.
    using browse_completion_handler = std::function<void(std::error_code, std::vector<resolved_service>)>;

    // Non-copyable (owns recv_loop by unique_ptr)
    service_discovery(const service_discovery &) = delete;
    service_discovery &operator=(const service_discovery &) = delete;

    // Movable only before async_discover()/async_browse() is called (loops must be null).
    service_discovery(service_discovery &&other) noexcept
        : m_socket(std::move(other.m_socket))
        , m_timer(std::move(other.m_timer))
        , m_silence_timeout(other.m_silence_timeout)
        , m_on_record(std::move(other.m_on_record))
        , m_on_completion(std::move(other.m_on_completion))
        , m_on_browse_completion(std::move(other.m_on_browse_completion))
        , m_loop(std::move(other.m_loop))
        , m_browse_loop(std::move(other.m_browse_loop))
        , m_results(std::move(other.m_results))
        , m_services(std::move(other.m_services))
    {
        assert(other.m_loop == nullptr);        // source must not have been started
        assert(other.m_browse_loop == nullptr); // source must not have been started
    }

    service_discovery &operator=(service_discovery &&) = delete;

    ~service_discovery()
    {
        m_loop.reset();
        m_browse_loop.reset();
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

#ifndef ASIO_STANDALONE
    // Non-template callback overload — used by NativePolicy and MockPolicy users.
    // Not compiled when ASIO_STANDALONE is defined to avoid ambiguity with the
    // template overload below (which also accepts plain std::function callbacks).
    void async_discover(std::string_view service_type, completion_handler on_done)
    {
        assert(m_loop == nullptr); // one discover per lifetime
        // Only store if non-empty — prevents wrapping an empty std::function in
        // move_only_function (which would evaluate as truthy but throw on call).
        if (on_done)
            m_on_completion = std::move(on_done);
        do_discover(std::string(service_type));
    }

    /// Aggregating browse — delivers resolved_service values via RFC 6763 name-chain
    /// correlation (PTR -> SRV -> TXT -> A/AAAA) at the silence timeout.
    /// Completion signature: void(std::error_code, std::vector<resolved_service>).
    void async_browse(std::string_view service_type, browse_completion_handler on_done)
    {
        assert(m_browse_loop == nullptr); // one browse per lifetime
        if (on_done)
            m_on_browse_completion = std::move(on_done);
        do_browse(std::string(service_type));
    }
#endif

#ifdef ASIO_STANDALONE
    /// ASIO completion token overload — accepts use_future, use_awaitable, deferred, or any callable.
    /// NativePolicy users (no ASIO_STANDALONE) use the non-template overload above instead.
    template <asio::completion_token_for<void(std::error_code, std::vector<mdns_record_variant>)>
                  CompletionToken>
    auto async_discover(std::string_view service_type, CompletionToken&& token)
    {
        return asio::async_initiate<
            CompletionToken,
            void(std::error_code, std::vector<mdns_record_variant>)>(
            [this](auto handler, std::string svc_type)
            {
                auto work = asio::make_work_guard(handler);

                // Type-erase into completion_handler, dispatching via the handler's executor.
                // The work guard is moved into the final dispatch lambda so it is released
                // only AFTER the handler executes, preventing premature io_context::run() return.
                m_on_completion = [h = std::move(handler), w = std::move(work)](
                    std::error_code ec, std::vector<mdns_record_variant> results) mutable
                {
                    auto ex    = w.get_executor();
                    auto alloc = asio::get_associated_allocator(
                        h, asio::recycling_allocator<void>());
                    asio::dispatch(ex,
                        asio::bind_allocator(alloc,
                            [h2 = std::move(h), w2 = std::move(w), ec, r = std::move(results)]() mutable
                            {
                                // w2 keeps io_context alive until this lambda executes.
                                (void)w2;
                                std::move(h2)(ec, std::move(r));
                            }));
                };

                do_discover(std::move(svc_type));
            },
            token,
            std::string(service_type));  // decay-copy string_view for deferred safety
    }

    /// ASIO completion token overload for async_browse.
    /// Aggregates mDNS records into resolved_service values at the silence timeout.
    /// Completion signature: void(std::error_code, std::vector<resolved_service>).
    template <asio::completion_token_for<void(std::error_code, std::vector<resolved_service>)>
                  CompletionToken>
    auto async_browse(std::string_view service_type, CompletionToken&& token)
    {
        return asio::async_initiate<
            CompletionToken,
            void(std::error_code, std::vector<resolved_service>)>(
            [this](auto handler, std::string svc_type)
            {
                auto work = asio::make_work_guard(handler);

                m_on_browse_completion = [h = std::move(handler), w = std::move(work)](
                    std::error_code ec, std::vector<resolved_service> services) mutable
                {
                    auto ex    = w.get_executor();
                    auto alloc = asio::get_associated_allocator(
                        h, asio::recycling_allocator<void>());
                    asio::dispatch(ex,
                        asio::bind_allocator(alloc,
                            [h2 = std::move(h), w2 = std::move(w), ec, s = std::move(services)]() mutable
                            {
                                (void)w2;
                                std::move(h2)(ec, std::move(s));
                            }));
                };

                do_browse(std::move(svc_type));
            },
            token,
            std::string(service_type));
    }
#endif

    // Access accumulated raw record results (populated during io.run()).
    // Remains valid after completion — the completion handler receives a copy.
    const std::vector<mdns_record_variant> &results() const noexcept
    {
        return m_results;
    }

    // Access aggregated resolved_service values produced by async_browse.
    // Populated at silence timeout (or stop()) — empty until browse completes.
    const std::vector<resolved_service> &services() const noexcept
    {
        return m_services;
    }

    // Early termination — stops the recv_loop(s) and fires the completion handler(s).
    void stop()
    {
        if (m_loop)
        {
            m_loop->stop();
            if (auto h = std::exchange(m_on_completion, nullptr); h)
                h(std::error_code{}, m_results);
        }
        if (m_browse_loop)
        {
            m_browse_loop->stop();
            m_services = mdnspp::aggregate(m_results);
            if (auto h = std::exchange(m_on_browse_completion, nullptr); h)
                h(std::error_code{}, m_services);
        }
    }

private:
    // Common browse body — assumes m_on_browse_completion is already set.
    // Mirrors do_discover() exactly; silence callback calls aggregate(m_results)
    // instead of firing the discover handler.
    // Must only be called once per lifetime (m_browse_loop must be null on entry).
    void do_browse(std::string svc_type)
    {
        assert(m_browse_loop == nullptr); // one browse per lifetime
        m_results.clear();
        m_service_type = std::move(svc_type);
        if (!m_service_type.empty() && m_service_type.back() == '.')
            m_service_type.pop_back();

        // Build and send DNS PTR query (qtype = 12) — same as do_discover()
        auto query_bytes = detail::build_dns_query(m_service_type, 12);
        m_socket.send(endpoint{"224.0.0.251", 5353},
                      std::span<const std::byte>(query_bytes));

        m_browse_loop = std::make_unique<recv_loop<P>>(
            m_socket,
            m_timer,
            m_silence_timeout,
            // on_packet: identical to do_discover() — accumulates into m_results,
            // fires m_on_record per relevant record.
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
            // on_silence: aggregate raw records into resolved_service values, fire handler
            [this]()
            {
                m_browse_loop->stop();
                m_services = mdnspp::aggregate(m_results);
                if (auto h = std::exchange(m_on_browse_completion, nullptr); h)
                    h(std::error_code{}, m_services);
            });

        m_browse_loop->start();
    }

    // Common discover body — assumes m_on_completion is already set.
    // Sets up m_service_type, sends DNS query, creates and starts recv_loop.
    // Must only be called once per lifetime (m_loop must be null on entry).
    void do_discover(std::string svc_type)
    {
        assert(m_loop == nullptr); // one discover per lifetime
        m_results.clear();
        m_service_type = std::move(svc_type);
        // Strip trailing dot so the name matches read_dns_name output (no trailing dot)
        if (!m_service_type.empty() && m_service_type.back() == '.')
            m_service_type.pop_back();

        // Build and send DNS PTR query (qtype = 12)
        auto query_bytes = detail::build_dns_query(m_service_type, 12);
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
            // on_silence: stop the loop and fire the completion handler with results
            [this]()
            {
                m_loop->stop();
                if (auto h = std::exchange(m_on_completion, nullptr); h)
                    h(std::error_code{}, m_results);
            });

        m_loop->start();
    }

    socket_type      m_socket;
    timer_type       m_timer;
    std::chrono::milliseconds m_silence_timeout;
    record_callback  m_on_record;            // optional per-record callback
    // Move-only function: supports both copyable std::function handlers (NativePolicy)
    // and move-only ASIO coroutine handlers (use_awaitable via ASIO_STANDALONE path).
    std::move_only_function<void(std::error_code, std::vector<mdns_record_variant>)>
        m_on_completion;                     // fires once at silence timeout or stop()
    std::move_only_function<void(std::error_code, std::vector<resolved_service>)>
        m_on_browse_completion;              // fires once at silence timeout or stop()
    std::string      m_service_type;         // set in do_discover()/do_browse(), used for filtering
    std::unique_ptr<recv_loop<P>> m_loop;    // null until async_discover()
    std::unique_ptr<recv_loop<P>> m_browse_loop; // null until async_browse()
    std::vector<mdns_record_variant> m_results;
    std::vector<resolved_service>    m_services; // populated by do_browse() at silence timeout
};

} // namespace mdnspp

#endif // HPP_GUARD_MDNSPP_SERVICE_DISCOVERY_H
