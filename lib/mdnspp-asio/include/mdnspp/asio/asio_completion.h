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

// A cancellation may be emitted from any executor: every peer's stop() is idempotent and callable from any thread.
template <typename Peer, typename Handler>
void bind_cancellation(Peer &peer, Handler &handler)
{
    auto slot = asio::get_associated_cancellation_slot(handler);
    if(slot.is_connected())
        slot.assign([&peer](asio::cancellation_type_t) { peer.stop(); });
}

// asio::cancel_after builds its timer on the initiation's executor, which serializes that timer with the
// operation's completion on the peer's io_context.
template <typename Peer>
struct peer_initiation
{
    Peer &peer;

    // Naming Peer::socket_type::executor_type trips an MSVC access check through the peer's private base.
    using executor_type = decltype(std::declval<Peer &>().socket().get_executor());

    executor_type get_executor() const noexcept
    {
        return peer.socket().get_executor();
    }
};

}

}

#endif

#endif
