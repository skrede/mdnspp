#ifndef HPP_GUARD_MDNSPP_ASIO_ASYNC_QUERY_H
#define HPP_GUARD_MDNSPP_ASIO_ASYNC_QUERY_H

#include "mdnspp/basic_querier.h"

#include "mdnspp/asio/asio_completion.h"

namespace mdnspp {

namespace detail {

template <policy_like P>
struct query_initiation : peer_initiation<basic_querier<P>>
{
    template <typename Handler>
    void operator()(Handler handler, std::string qname, dns_type qt, response_mode mode) const
    {
        basic_querier<P> &q = this->peer;
        bind_cancellation(q, handler);
        auto work = asio::make_work_guard(handler);
        q.async_query(std::move(qname), qt,
                      [h = std::move(handler), w = std::move(work)](std::error_code ec, std::vector<mdns_record_variant> results) mutable
                      {
                          mdnspp::dispatch_completion(std::move(h), std::move(w), ec, std::move(results));
                      },
                      mode);
    }
};

}

/// Issue a one-shot mDNS query for (`name`, `qtype`) on `q`.
///
/// Completion signature: void(std::error_code, std::vector<mdns_record_variant>).
/// Completes with std::error_code{} and the accumulated records at the
/// silence timeout, or with std::errc::operation_canceled and the partial
/// results when q.stop() ends the query early. Honors the completion
/// handler's associated cancellation slot: a requested cancellation calls
/// q.stop().
template <policy_like P,
    asio::completion_token_for<void(std::error_code, std::vector<mdns_record_variant>)>
    CompletionToken>
auto async_query(basic_querier<P> &q, std::string_view name, dns_type qtype,
                 CompletionToken &&token, response_mode mode = response_mode::multicast)
{
    return asio::async_initiate<
        CompletionToken,
        void(std::error_code, std::vector<mdns_record_variant>)>(
        detail::query_initiation<P>{{q}}, token, std::string(name), qtype, mode);
}

}

#endif
