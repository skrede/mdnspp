#ifndef HPP_GUARD_MDNSPP_ASIO_ASYNC_OBSERVE_H
#define HPP_GUARD_MDNSPP_ASIO_ASYNC_OBSERVE_H

#include "mdnspp/basic_observer.h"

#include "mdnspp/asio/asio_completion.h"

namespace mdnspp {

namespace detail {

template <policy_like P>
struct observe_initiation : peer_initiation<basic_observer<P>>
{
    template <typename Handler>
    void operator()(Handler handler) const
    {
        basic_observer<P> &obs = this->peer;
        bind_cancellation(obs, handler);
        auto work = asio::make_work_guard(handler);
        obs.async_observe([h = std::move(handler), w = std::move(work)](std::error_code ec) mutable
        {
            mdnspp::dispatch_completion(std::move(h), std::move(w), ec);
        });
    }
};

}

/// Begin observing mDNS multicast traffic on `obs`.
///
/// Completion signature: void(std::error_code). The observation has no
/// natural completion; the token completes with
/// std::errc::operation_canceled when obs.stop() ends it, or with the
/// observer's one-shot misuse codes (std::errc::operation_in_progress,
/// std::errc::invalid_argument). Honors the completion handler's associated
/// cancellation slot: a requested cancellation calls obs.stop().
template <policy_like P, asio::completion_token_for<void(std::error_code)> CompletionToken>
auto async_observe(basic_observer<P> &obs, CompletionToken &&token)
{
    return asio::async_initiate<CompletionToken, void(std::error_code)>(
        detail::observe_initiation<P>{{obs}}, token);
}

}

#endif
