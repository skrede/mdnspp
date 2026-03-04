#ifndef HPP_GUARD_MDNSPP_ASIO_ASIO_COMPLETION_H
#define HPP_GUARD_MDNSPP_ASIO_ASIO_COMPLETION_H

// asio_completion.h — ASIO dispatch helper for mdnspp completion handlers.
// The entire content is guarded by ASIO_STANDALONE so that headers including
// this file compile cleanly even when ASIO is not present in the build.

#ifdef ASIO_STANDALONE

#include <asio/async_result.hpp>
#include <asio/dispatch.hpp>
#include <asio/executor_work_guard.hpp>
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
void dispatch_completion(Handler handler, WorkGuard work, Args&&... args)
{
    auto ex    = work.get_executor();
    auto alloc = asio::get_associated_allocator(
        handler, asio::recycling_allocator<void>());
    asio::dispatch(ex,
        asio::bind_allocator(alloc,
            [h = std::move(handler),
             w = std::move(work),
             ...a = std::forward<Args>(args)]() mutable
            {
                (void)w;
                std::move(h)(std::move(a)...);
            }));
}

} // namespace mdnspp

#endif // ASIO_STANDALONE

#endif // HPP_GUARD_MDNSPP_ASIO_ASIO_COMPLETION_H
