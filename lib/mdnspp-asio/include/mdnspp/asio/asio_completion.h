#ifndef HPP_GUARD_MDNSPP_ASIO_ASIO_COMPLETION_H
#define HPP_GUARD_MDNSPP_ASIO_ASIO_COMPLETION_H

#ifdef MDNSPP_ENABLE_ASIO_POLICY

#include <asio/dispatch.hpp>
#include <asio/bind_allocator.hpp>
#include <asio/cancellation_type.hpp>
#include <asio/recycling_allocator.hpp>
#include <asio/associated_allocator.hpp>
#include <asio/associated_cancellation_slot.hpp>

#include <utility>

namespace mdnspp {

/// Dispatch a completion handler back onto its associated executor.
///
/// Moves `handler` and all completion arguments onto the executor associated
/// with `work`, using the handler's associated allocator.  The work guard
/// `w` is kept alive inside the lambda until after the handler executes,
/// ensuring the executor does not run out of work prematurely.  The
/// handler's associated cancellation slot is cleared before invocation, per
/// asio guidelines for completion of cancellable operations.
template <typename Handler, typename WorkGuard, typename... Args>
void dispatch_completion(Handler handler, WorkGuard work, Args &&... args)
{
    auto ex = work.get_executor();
    auto alloc = asio::get_associated_allocator(
        handler, asio::recycling_allocator<void>());
    asio::dispatch(ex, asio::bind_allocator(alloc, [h = std::move(handler), w = std::move(work), ...a = std::forward<Args>(args)]() mutable
    {
        (void)w;
        if(auto slot = asio::get_associated_cancellation_slot(h); slot.is_connected())
            slot.clear();
        std::move(h)(std::move(a)...);
    }));
}

namespace detail {

/// Connect the completion handler's associated cancellation slot to
/// peer.stop().  Every peer's stop() is idempotent and callable from any
/// thread (atomic stop flag plus posted teardown), so emission from an
/// arbitrary executor context is safe.  The completion then arrives through
/// the peer's own stop semantics (std::errc::operation_canceled for
/// observe/query/discover/browse and for a server that is not yet live).
template <typename Peer, typename Handler>
void bind_cancellation(Peer &peer, Handler &handler)
{
    auto slot = asio::get_associated_cancellation_slot(handler);
    if(slot.is_connected())
        slot.assign([&peer](asio::cancellation_type_t) { peer.stop(); });
}

/// Base for the async_* adapter initiation function objects.  Exposes the
/// peer's I/O executor as asio requires for initiations of cancellable
/// composed operations: asio::cancel_after constructs its internal timer on
/// Initiation::executor_type via get_executor(), which serializes the timer
/// with the operation's completion on the peer's io_context.
template <typename Peer>
struct peer_initiation
{
    Peer &peer;

    using executor_type = typename Peer::socket_type::executor_type;

    executor_type get_executor() const noexcept
    {
        return peer.socket().get_executor();
    }
};

}

}

#endif

#endif
