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

/// Shared completion state for async_run: the token may be completed either
/// by the server's on_done event (the normal path) or by a synchronous
/// on_ready misuse invocation during initiation, after which on_done never
/// fires.
template <typename Handler, typename Work>
struct run_state
{
    run_state(Handler h, Work w)
        : handler(std::move(h))
        , work(std::move(w))
    {
    }

    Handler handler;
    Work work;
    std::atomic<bool> in_initiation{true};
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
                // on_ready is invoked synchronously (still inside the
                // initiation) only on the server's one-shot misuse paths
                // (start after stop(): invalid_argument; double start:
                // operation_in_progress), after which on_done never fires.
                // All other on_ready outcomes are posted to the executor and
                // are followed by on_done, so they are ignored here.
                if(!state->in_initiation.load(std::memory_order_acquire))
                    return;
                if(state->completed.exchange(true, std::memory_order_acq_rel))
                    return;
                mdnspp::dispatch_completion(std::move(state->handler), std::move(state->work), ec);
            },
            [state](std::error_code ec)
            {
                if(state->completed.exchange(true, std::memory_order_acq_rel))
                    return;
                mdnspp::dispatch_completion(std::move(state->handler), std::move(state->work), ec);
            });
        state->in_initiation.store(false, std::memory_order_release);
    }
};

}

/// Start the service server and complete when it is READY.
///
/// The completion token binds the server's on_ready event. Completion
/// signature: void(std::error_code). The token completes with
/// - std::error_code{} once the probe -> announce sequence finishes and the
///   server is live (the server keeps running after completion; end it with
///   srv.stop()),
/// - mdns_error::probe_conflict on an unresolvable name conflict (the full
///   teardown has run by the time on_done would fire; the server is defunct),
/// - std::errc::invalid_argument on an unencodable name, after stop(), or on
///   reuse of a stopped server,
/// - std::errc::operation_in_progress if the server was already started,
/// - std::errc::operation_canceled when srv.stop() is called before the
///   server becomes live.
///
/// Honors the completion handler's associated cancellation slot: a requested
/// cancellation calls srv.stop(), which completes the token with
/// std::errc::operation_canceled if the server is not yet live.
///
/// To await full shutdown instead, use async_run().
template <policy_like P, asio::completion_token_for<void(std::error_code)> CompletionToken>
auto async_start(basic_service_server<P> &srv, CompletionToken &&token)
{
    return asio::async_initiate<CompletionToken, void(std::error_code)>(
        detail::start_initiation<P>{{srv}}, token);
}

/// Start the service server and complete after full TEARDOWN
/// (run-until-stopped).
///
/// The completion token binds the server's on_done event. Completion
/// signature: void(std::error_code). The token completes with
/// - std::error_code{} after srv.stop() has run the full teardown (goodbye
///   send included) -- also when startup failed permanently
///   (probe conflict or unencodable name), since the teardown runs and
///   on_done fires with std::error_code{} on that path as well; observe the
///   startup outcome with async_start() or the on_ready callback if it is
///   needed,
/// - std::errc::invalid_argument when called after stop(),
/// - std::errc::operation_in_progress when the server was already started.
///
/// Honors the completion handler's associated cancellation slot: a requested
/// cancellation calls srv.stop(), so the token then completes with
/// std::error_code{} after the teardown.
template <policy_like P, asio::completion_token_for<void(std::error_code)> CompletionToken>
auto async_run(basic_service_server<P> &srv, CompletionToken &&token)
{
    return asio::async_initiate<CompletionToken, void(std::error_code)>(
        detail::run_initiation<P>{{srv}}, token);
}

}

#endif
