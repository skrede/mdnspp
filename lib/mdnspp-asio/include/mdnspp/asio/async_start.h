#ifndef HPP_GUARD_MDNSPP_ASIO_ASYNC_START_H
#define HPP_GUARD_MDNSPP_ASIO_ASYNC_START_H

#include "mdnspp/asio/asio_completion.h"

#include "mdnspp/basic_service_server.h"

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
    Work work;
    Handler handler;
    std::atomic<bool> completed;

    run_state(Handler h, Work w)
        : work(std::move(w))
        , handler(std::move(h))
        , completed(false)
    {
    }

    void complete(std::error_code ec)
    {
        if(completed.exchange(true, std::memory_order_acq_rel))
            return;
        mdnspp::dispatch_completion(std::move(handler), std::move(work), ec);
    }

    // On the misuse paths (double start, start after stop()) on_done never fires, so the token completes here. An
    // unencodable name also reports invalid_argument here; the completed flag then drops the on_done that follows.
    void ready(std::error_code ec)
    {
        if(ec == std::errc::operation_in_progress
           || ec == std::errc::invalid_argument)
            complete(ec);
    }
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
