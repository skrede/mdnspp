#pragma once

#ifdef ASIO_STANDALONE
#include "mdnspp/observer.h"
#include "mdnspp/asio/asio_completion.h"

namespace mdnspp {

template <Policy P,
          asio::completion_token_for<void(std::error_code)> CompletionToken>
auto async_observe(observer<P> &obs, CompletionToken &&token)
{
    return asio::async_initiate<CompletionToken, void(std::error_code)>(
        [&obs](auto handler)
        {
            auto work = asio::make_work_guard(handler);
            obs.async_observe(
                [h = std::move(handler), w = std::move(work)](std::error_code ec) mutable
                {
                    mdnspp::dispatch_completion(std::move(h), std::move(w), ec);
                });
        },
        token);
}

} // namespace mdnspp

#endif // ASIO_STANDALONE
