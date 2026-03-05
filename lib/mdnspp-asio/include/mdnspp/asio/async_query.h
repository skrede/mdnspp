#ifndef HPP_GUARD_MDNSPP_ASYNC_QUERY_H
#define HPP_GUARD_MDNSPP_ASYNC_QUERY_H

#include "mdnspp/asio/asio_completion.h"

#include <mdnspp/basic_querier.h>

namespace mdnspp {

template <Policy P,
    asio::completion_token_for<void(std::error_code, std::vector<mdns_record_variant>)>
    CompletionToken>
auto async_query(basic_querier<P> &q, std::string_view name, dns_type qtype, CompletionToken &&token)
{
    return asio::async_initiate<
        CompletionToken,
        void(std::error_code, std::vector<mdns_record_variant>)>(
        [&q](auto handler, std::string qname, dns_type qt)
        {
            auto work = asio::make_work_guard(handler);
            q.async_query(std::move(qname), qt,
                          [h = std::move(handler), w = std::move(work)](std::error_code ec, std::vector<mdns_record_variant> results) mutable
                          {
                              mdnspp::dispatch_completion(std::move(h), std::move(w), ec, std::move(results));
                          });
        },
        token, std::string(name), qtype);
}

}

#endif
