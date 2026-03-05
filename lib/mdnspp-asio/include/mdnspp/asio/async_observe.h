#ifndef HPP_GUARD_MDNSPP_ASYNC_OBSERVE_H
#define HPP_GUARD_MDNSPP_ASYNC_OBSERVE_H

#include "mdnspp/asio/asio_completion.h"

#include <mdnspp/observer.h>

namespace mdnspp {

template <Policy P, asio::completion_token_for<void(std::error_code)> CompletionToken>
auto async_observe(observer<P> &obs, CompletionToken &&token)
{
    return asio::async_initiate<CompletionToken, void(std::error_code)>(
        [&obs](auto handler)
        {
            auto work = asio::make_work_guard(handler);
            obs.async_observe([h = std::move(handler), w = std::move(work)](std::error_code ec) mutable
            {
                mdnspp::dispatch_completion(std::move(h), std::move(w), ec);
            });
        },
        token);
}

}

#endif
