#ifndef HPP_GUARD_MDNSPP_TIMER_POLICY_H
#define HPP_GUARD_MDNSPP_TIMER_POLICY_H

#include <chrono>
#include <functional>
#include <system_error>

namespace mdnspp {

template <typename T>
concept TimerPolicy = requires(
    T &t,
    std::chrono::milliseconds dur,
    std::function<void(std::error_code)> handler)
{
    t.expires_after(dur);                  // no return constraint — asio::steady_timer returns std::size_t
    { t.async_wait(handler) } -> std::same_as<void>;
    { t.cancel() } -> std::same_as<void>;
};

} // namespace mdnspp

#endif // HPP_GUARD_MDNSPP_TIMER_POLICY_H
