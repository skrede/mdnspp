#pragma once

#ifdef ASIO_STANDALONE
#include "mdnspp/service_discovery.h"
#include "mdnspp/asio/asio_completion.h"

namespace mdnspp {

template <Policy P,
          asio::completion_token_for<void(std::error_code, std::vector<mdns_record_variant>)>
              CompletionToken>
auto async_discover(service_discovery<P> &sd, std::string_view service_type, CompletionToken &&token)
{
    return asio::async_initiate<
        CompletionToken,
        void(std::error_code, std::vector<mdns_record_variant>)>(
        [&sd](auto handler, std::string svc_type)
        {
            auto work = asio::make_work_guard(handler);
            sd.async_discover(std::move(svc_type),
                [h = std::move(handler), w = std::move(work)](
                    std::error_code ec, std::vector<mdns_record_variant> results) mutable
                {
                    mdnspp::dispatch_completion(std::move(h), std::move(w), ec, std::move(results));
                });
        },
        token,
        std::string(service_type));
}

template <Policy P,
          asio::completion_token_for<void(std::error_code, std::vector<resolved_service>)>
              CompletionToken>
auto async_browse(service_discovery<P> &sd, std::string_view service_type, CompletionToken &&token)
{
    return asio::async_initiate<
        CompletionToken,
        void(std::error_code, std::vector<resolved_service>)>(
        [&sd](auto handler, std::string svc_type)
        {
            auto work = asio::make_work_guard(handler);
            sd.async_browse(std::move(svc_type),
                [h = std::move(handler), w = std::move(work)](
                    std::error_code ec, std::vector<resolved_service> services) mutable
                {
                    mdnspp::dispatch_completion(std::move(h), std::move(w), ec, std::move(services));
                });
        },
        token,
        std::string(service_type));
}

} // namespace mdnspp

#endif // ASIO_STANDALONE
