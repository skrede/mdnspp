#ifndef HPP_GUARD_MDNSPP_QUERENT_H
#define HPP_GUARD_MDNSPP_QUERENT_H

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
#include <cstdint>
#include <cassert>
#include <system_error>
#include <utility>

#include "mdnspp/detail/recv_loop.h"
#include "mdnspp/detail/dns_wire.h"

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
class querent
{
public:
    using executor_type = typename P::executor_type;
    using socket_type = typename P::socket_type;
    using timer_type = typename P::timer_type;

    /// Optional callback invoked per record as results arrive during a query.
    using record_callback = std::function<void(const mdns_record_variant &, endpoint)>;

    /// Completion callback fired once when the silence timeout expires (or stop() is called).
    /// Receives error_code (always success for normal completion) and the accumulated results.
    using completion_handler = std::function<void(std::error_code, std::vector<mdns_record_variant>)>;

    // Non-copyable (owns recv_loop by unique_ptr)
    querent(const querent &) = delete;
    querent &operator=(const querent &) = delete;

    // Movable only before async_query() is called (m_loop must be null).
    querent(querent &&other) noexcept
        : m_socket(std::move(other.m_socket))
        , m_timer(std::move(other.m_timer))
        , m_silence_timeout(other.m_silence_timeout)
        , m_on_record(std::move(other.m_on_record))
        , m_on_completion(std::move(other.m_on_completion))
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

    // Throwing constructor — constructs socket and timer from executor.
    // Silence timeout determines how long to wait after the last relevant packet
    // before stopping the recv_loop.
    explicit querent(executor_type ex,
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
    querent(executor_type ex,
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

    querent(executor_type ex,
            std::chrono::milliseconds silence_timeout,
            std::error_code &ec)
        : m_socket(ex, ec)
        , m_timer(ex)
        , m_silence_timeout(silence_timeout)
        , m_loop(nullptr)
    {
    }

    // Accessors — querent owns socket and timer directly.
    const socket_type &socket() const noexcept { return m_socket; }
    socket_type &socket() noexcept { return m_socket; }
    const timer_type &timer() const noexcept { return m_timer; }
    timer_type &timer() noexcept { return m_timer; }

#ifndef ASIO_STANDALONE
    // Non-template callback overload — used by NativePolicy and MockPolicy users.
    // Not compiled when ASIO_STANDALONE is defined to avoid ambiguity with the
    // template overload below (which also accepts plain std::function callbacks).
    void async_query(std::string_view name, uint16_t qtype, completion_handler on_done)
    {
        assert(m_loop == nullptr); // one query per lifetime
        // Only store if non-empty — prevents wrapping an empty std::function in
        // move_only_function (which would evaluate as truthy but throw on call).
        if(on_done)
            m_on_completion = std::move(on_done);
        do_query(std::string(name), qtype);
    }
#endif

#ifdef ASIO_STANDALONE
    /// ASIO completion token overload — accepts use_future, use_awaitable, deferred, or any callable.
    /// NativePolicy users (no ASIO_STANDALONE) use the non-template overload above instead.
    template <asio::completion_token_for<void(std::error_code, std::vector<mdns_record_variant>)>
        CompletionToken>
    auto async_query(std::string_view name, uint16_t qtype, CompletionToken &&token)
    {
        return asio::async_initiate<
            CompletionToken,
            void(std::error_code, std::vector<mdns_record_variant>)>(
            [this](auto handler, std::string qname, uint16_t qt)
            {
                auto work = asio::make_work_guard(handler);

                // Type-erase into completion_handler, dispatching via the handler's executor.
                // The work guard is moved into the final dispatch lambda so it is released
                // only AFTER the handler executes, preventing premature io_context::run() return.
                m_on_completion = [h = std::move(handler), w = std::move(work)](
                    std::error_code ec, std::vector<mdns_record_variant> results) mutable
                    {
                        auto ex = w.get_executor();
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

                do_query(std::move(qname), qt);
            },
            token,
            std::string(name), // decay-copy string_view for deferred safety
            qtype);            // trivial copy
    }
#endif

    // Access accumulated results (populated during io.run()).
    // Remains valid after completion — the completion handler receives a copy.
    const std::vector<mdns_record_variant> &results() const noexcept
    {
        return m_results;
    }

    // Early termination — stops the recv_loop and fires the completion handler.
    void stop()
    {
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
    void do_query(std::string qname, uint16_t qtype)
    {
        assert(m_loop == nullptr); // one query per lifetime
        m_results.clear();
        m_query_name = std::move(qname);
        // Strip trailing dot so the name matches read_dns_name output (no trailing dot)
        if(!m_query_name.empty() && m_query_name.back() == '.')
            m_query_name.pop_back();

        // Build and send DNS query for the requested name and qtype
        auto query_bytes = detail::build_dns_query(m_query_name, qtype);
        m_socket.send(endpoint{"224.0.0.251", 5353},
                      std::span<const std::byte>(query_bytes));

        m_loop = std::make_unique<recv_loop<P>>(
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

                if(relevant)
                {
                    if(m_on_record)
                    {
                        for(const auto &rec : batch)
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
                if(auto h = std::exchange(m_on_completion, nullptr); h)
                    h(std::error_code{}, m_results);
            });

        m_loop->start();
    }

    socket_type m_socket;
    timer_type m_timer;
    std::chrono::milliseconds m_silence_timeout;
    record_callback m_on_record; // optional per-record callback
    // Move-only function: supports both copyable std::function handlers (NativePolicy)
    // and move-only ASIO coroutine handlers (use_awaitable via ASIO_STANDALONE path).
    std::move_only_function<void(std::error_code, std::vector<mdns_record_variant>)>
    m_on_completion;                      // fires once at silence timeout or stop()
    std::string m_query_name;             // set in do_query(), used for filtering
    std::unique_ptr<recv_loop<P>> m_loop; // null until async_query()
    std::vector<mdns_record_variant> m_results;
};

}

#endif
