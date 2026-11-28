#ifndef HPP_GUARD_MDNSPP_SUPPORT_SYNC_WAIT_H
#define HPP_GUARD_MDNSPP_SUPPORT_SYNC_WAIT_H

#include <chrono>
#include <future>
#include <memory>
#include <thread>

namespace mdnspp::test_support {

template <typename Predicate>
bool wait_until(Predicate done, std::chrono::milliseconds deadline)
{
    const auto expiry = std::chrono::steady_clock::now() + deadline;
    while(!done())
    {
        if(std::chrono::steady_clock::now() >= expiry)
            return false;
        std::this_thread::sleep_for(std::chrono::milliseconds{1});
    }
    return true;
}

// The posted function owns the promise, so a timed-out wait leaves nothing dangling.
template <typename Post>
bool round_trip(Post post, std::chrono::milliseconds deadline)
{
    auto marker = std::make_shared<std::promise<void>>();
    std::future<void> reached = marker->get_future();
    post([marker] { marker->set_value(); });
    return reached.wait_for(deadline) == std::future_status::ready;
}

}

#endif
