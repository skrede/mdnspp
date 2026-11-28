#ifndef HPP_GUARD_MDNSPP_ASIO_ASYNC_DISCOVER_H
#define HPP_GUARD_MDNSPP_ASIO_ASYNC_DISCOVER_H

#include "mdnspp/asio/asio_completion.h"

#include "mdnspp/basic_service_discovery.h"

namespace mdnspp {

namespace detail {

template <policy_like P>
struct discover_initiation : peer_initiation<basic_service_discovery<P>>
{
    template <typename Handler>
    void operator()(Handler handler, std::string svc_type, response_mode mode) const
    {
        basic_service_discovery<P> &sd = this->peer;
        bind_cancellation(sd, handler);
        auto work = asio::make_work_guard(handler);
        sd.async_discover(std::move(svc_type),
                          [h = std::move(handler), w = std::move(work)](
                          std::error_code ec, std::vector<mdns_record_variant> results) mutable
                          {
                              mdnspp::dispatch_completion(std::move(h), std::move(w), ec, std::move(results));
                          },
                          mode);
    }
};

template <policy_like P>
struct browse_initiation : peer_initiation<basic_service_discovery<P>>
{
    template <typename Handler>
    void operator()(Handler handler, std::string svc_type, response_mode mode) const
    {
        basic_service_discovery<P> &sd = this->peer;
        bind_cancellation(sd, handler);
        auto work = asio::make_work_guard(handler);
        sd.async_browse(std::move(svc_type),
                        [h = std::move(handler), w = std::move(work)](
                        std::error_code ec, std::vector<resolved_service> services) mutable
                        {
                            mdnspp::dispatch_completion(std::move(h), std::move(w), ec, std::move(services));
                        },
                        mode);
    }
};

}

template <policy_like P, asio::completion_token_for<void(std::error_code, std::vector<mdns_record_variant>)>CompletionToken>
auto async_discover(basic_service_discovery<P> &sd, std::string_view service_type,
                    CompletionToken &&token, response_mode mode = response_mode::multicast)
{
    return asio::async_initiate<
        CompletionToken,
        void(std::error_code, std::vector<mdns_record_variant>)>(
        detail::discover_initiation<P>{{sd}}, token, std::string(service_type), mode);
}

template <policy_like P, asio::completion_token_for<void(std::error_code, std::vector<resolved_service>)>CompletionToken>
auto async_browse(basic_service_discovery<P> &sd, std::string_view service_type,
                  CompletionToken &&token, response_mode mode = response_mode::multicast)
{
    return asio::async_initiate<
        CompletionToken,
        void(std::error_code, std::vector<resolved_service>)>(
        detail::browse_initiation<P>{{sd}}, token, std::string(service_type), mode);
}

}

#endif
