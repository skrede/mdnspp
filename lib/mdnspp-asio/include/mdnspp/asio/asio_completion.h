#ifndef HPP_GUARD_MDNSPP_ASIO_COMPLETION_H
#define HPP_GUARD_MDNSPP_ASIO_COMPLETION_H

#ifdef MDNSPP_ENABLE_ASIO_POLICY

#include <asio/dispatch.hpp>
#include <asio/bind_allocator.hpp>
#include <asio/recycling_allocator.hpp>
#include <asio/associated_allocator.hpp>

namespace mdnspp {

/// Dispatch a completion handler back onto its associated executor.
///
/// Moves `handler` and all completion arguments onto the executor associated
/// with `work`, using the handler's associated allocator.  The work guard
/// `w` is kept alive inside the lambda until after the handler executes,
/// ensuring the executor does not run out of work prematurely.
template <typename Handler, typename WorkGuard, typename... Args>
void dispatch_completion(Handler handler, WorkGuard work, Args &&... args)
{
    auto ex = work.get_executor();
    auto alloc = asio::get_associated_allocator(
        handler, asio::recycling_allocator<void>());
    asio::dispatch(ex, asio::bind_allocator(alloc, [h = std::move(handler), w = std::move(work), ...a = std::forward<Args>(args)]() mutable
    {
        (void)w;
        std::move(h)(std::move(a)...);
    }));
}

}

#endif

#endif
