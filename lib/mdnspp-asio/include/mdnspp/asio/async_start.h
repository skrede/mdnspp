#ifndef HPP_GUARD_MDNSPP_ASYNC_START_H
#define HPP_GUARD_MDNSPP_ASYNC_START_H

#include "mdnspp/asio/asio_completion.h"

#include <mdnspp/basic_service_server.h>

namespace mdnspp {

template <Policy P, asio::completion_token_for<void(std::error_code)> CompletionToken>
auto async_start(basic_service_server<P> &srv, CompletionToken &&token)
{
    return asio::async_initiate<CompletionToken, void(std::error_code)>(
        [&srv](auto handler)
        {
            auto work = asio::make_work_guard(handler);
            srv.async_start({},
                [h = std::move(handler), w = std::move(work)](std::error_code ec) mutable
                {
                    mdnspp::dispatch_completion(std::move(h), std::move(w), ec);
                });
        },
        token);
}

}

#endif
