#pragma once

#ifdef ASIO_STANDALONE
#include "mdnspp/service_server.h"
#include "mdnspp/asio/asio_completion.h"

namespace mdnspp {

template <Policy P,
          asio::completion_token_for<void(std::error_code)> CompletionToken>
auto async_start(service_server<P> &srv, CompletionToken &&token)
{
    return asio::async_initiate<CompletionToken, void(std::error_code)>(
        [&srv](auto handler)
        {
            auto work = asio::make_work_guard(handler);
            srv.async_start(
                [h = std::move(handler), w = std::move(work)](std::error_code ec) mutable
                {
                    mdnspp::dispatch_completion(std::move(h), std::move(w), ec);
                });
        },
        token);
}

} // namespace mdnspp

#endif // ASIO_STANDALONE
