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

/// Shared completion state for async_run: the token is completed by the
/// FIRST of the server's on_ready event carrying a code for which on_done
/// can never fire (the one-shot misuse paths) and the on_done event itself.
/// The atomic completed flag guarantees exactly-once completion on paths
/// where both events fire (abort_startup delivers on_ready with a failure
/// reason and on_done immediately after the teardown).
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
                if(ec == std::errc::operation_in_progress
                   || ec == std::errc::invalid_argument)
                    state->complete(ec);
            },
            [state](std::error_code ec)
            {
                state->complete(ec);
            });
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
/// The completion token completes on the first of the server's on_done event
/// and an on_ready event whose code implies on_done can never fire.
/// Completion signature: void(std::error_code). The token completes with
/// - std::error_code{} after srv.stop() has run the full teardown (goodbye
///   send included) -- also on an unresolvable probe conflict, since the
///   teardown runs and on_done fires with std::error_code{} on that path as
///   well; observe the startup outcome with async_start() or the on_ready
///   callback if it is needed,
/// - std::errc::invalid_argument when called after stop() (on_done never
///   fires on this misuse path) and on an unencodable name (on_ready
///   delivers the reason before the teardown's on_done and wins the
///   exactly-once completion),
/// - std::errc::operation_in_progress when the server was already started
///   (on_done never fires on this misuse path).
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
