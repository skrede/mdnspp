#ifndef HPP_GUARD_MDNSPP_ASIO_ASYNC_START_H
#define HPP_GUARD_MDNSPP_ASIO_ASYNC_START_H

#include "mdnspp/basic_service_server.h"

#include "mdnspp/asio/asio_completion.h"

#include <atomic>
#include <memory>
#include <utility>

namespace mdnspp {

namespace detail {

template <policy_like P>
struct start_initiation : peer_initiation<basic_service_server<P>>
{
    template <typename Handler>
    void operator()(Handler handler) const
    {
        basic_service_server<P> &srv = this->peer;
        bind_cancellation(srv, handler);
        auto work = asio::make_work_guard(handler);
        srv.async_start([h = std::move(handler), w = std::move(work)](std::error_code ec) mutable
        {
            mdnspp::dispatch_completion(std::move(h), std::move(w), ec);
        });
    }
};

template <typename Handler, typename Work>
struct run_state
{
    run_state(Handler h, Work w)
        : handler(std::move(h))
        , work(std::move(w))
    {
    }

    void complete(std::error_code ec)
    {
        if(completed.exchange(true, std::memory_order_acq_rel))
            return;
        mdnspp::dispatch_completion(std::move(handler), std::move(work), ec);
    }

    // Derived from basic_service_server: on the one-shot misuse
    // paths (double start: operation_in_progress; start after
    // stop(): invalid_argument) async_start posts on_ready and
    // returns without storing the handlers, so on_done can never
    // fire -- the token must complete here. abort_startup also
    // delivers invalid_argument through on_ready (unencodable
    // name) but follows it with on_done; the completed flag lets
    // this on_ready win and drops the subsequent on_done. All
    // other on_ready outcomes ({}: live, operation_canceled:
    // stop() before live, mdns_error::probe_conflict) are
    // followed by on_done, which completes the token.
    void ready(std::error_code ec)
    {
        if(ec == std::errc::operation_in_progress
           || ec == std::errc::invalid_argument)
            complete(ec);
    }

    Handler handler;
    Work work;
    std::atomic<bool> completed{false};
};

template <policy_like P>
struct run_initiation : peer_initiation<basic_service_server<P>>
{
    template <typename Handler>
    void operator()(Handler handler) const
    {
        basic_service_server<P> &srv = this->peer;
        bind_cancellation(srv, handler);
        auto work = asio::make_work_guard(handler);
        auto state = std::make_shared<run_state<Handler, decltype(work)>>(
            std::move(handler), std::move(work));
        srv.async_start(
            [state](std::error_code ec)
            {
                state->ready(ec);
            },
            [state](std::error_code ec)
            {
                state->complete(ec);
            });
    }
};

}

template <policy_like P, asio::completion_token_for<void(std::error_code)> CompletionToken>
auto async_start(basic_service_server<P> &srv, CompletionToken &&token)
{
    return asio::async_initiate<CompletionToken, void(std::error_code)>(
        detail::start_initiation<P>{{srv}}, token);
}

template <policy_like P, asio::completion_token_for<void(std::error_code)> CompletionToken>
auto async_run(basic_service_server<P> &srv, CompletionToken &&token)
{
    return asio::async_initiate<CompletionToken, void(std::error_code)>(
        detail::run_initiation<P>{{srv}}, token);
}

}

#endif
