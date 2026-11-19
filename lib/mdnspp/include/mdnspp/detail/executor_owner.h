#ifndef HPP_GUARD_MDNSPP_DETAIL_EXECUTOR_OWNER_H
#define HPP_GUARD_MDNSPP_DETAIL_EXECUTOR_OWNER_H

#ifndef NDEBUG
#  include <atomic>
#  include <thread>
#  include <cassert>
#endif

namespace mdnspp::detail {

#ifndef NDEBUG

class executor_claim
{
public:
    executor_claim(std::atomic<std::thread::id> &thread, bool claimed) noexcept
        : m_thread{thread}
        , m_claimed{claimed}
    {
    }

    ~executor_claim()
    {
        if(m_claimed)
            m_thread.store(std::thread::id{}, std::memory_order_release);
    }

    executor_claim(const executor_claim &) = delete;
    executor_claim &operator=(const executor_claim &) = delete;

private:
    std::atomic<std::thread::id> &m_thread;
    bool m_claimed;
};

class executor_owner
{
public:
    executor_owner()
        : m_thread{}
    {
    }

    // A nested claim from inside the loop finds its own id and leaves the outer claim in place.
    executor_claim claim() noexcept
    {
        std::thread::id unclaimed{};
        const bool claimed = m_thread.compare_exchange_strong(unclaimed, std::this_thread::get_id(),
                                                              std::memory_order_acq_rel);
        return executor_claim{m_thread, claimed};
    }

    void assert_current() const noexcept
    {
        const std::thread::id owner = m_thread.load(std::memory_order_acquire);
        assert((owner == std::thread::id{} || owner == std::this_thread::get_id())
               && "executor state used from a thread other than the one running the loop");
    }

private:
    std::atomic<std::thread::id> m_thread;
};

#else

class executor_claim
{
public:
    // User-provided so that a held but unused claim does not trigger an unused-variable warning.
    executor_claim() noexcept
    {
    }

    ~executor_claim()
    {
    }

    executor_claim(const executor_claim &) = delete;
    executor_claim &operator=(const executor_claim &) = delete;
};

class executor_owner
{
public:
    executor_claim claim() noexcept
    {
        return executor_claim{};
    }

    void assert_current() const noexcept
    {
    }
};

#endif

}

#endif
