#ifndef HPP_GUARD_MDNSPP_DETAIL_EXECUTOR_OWNER_H
#define HPP_GUARD_MDNSPP_DETAIL_EXECUTOR_OWNER_H

#ifndef NDEBUG
#  include <atomic>
#  include <thread>
#  include <cassert>
#endif

namespace mdnspp::detail {

#ifndef NDEBUG

class executor_owner
{
public:
    executor_owner()
        : m_claimed{false}
        , m_thread{}
    {
    }

    void claim() noexcept
    {
        if(!m_claimed.exchange(true, std::memory_order_acq_rel))
            m_thread = std::this_thread::get_id();
    }

    void assert_current() const noexcept
    {
        if(m_claimed.load(std::memory_order_acquire))
            assert(std::this_thread::get_id() == m_thread && "executor state used from a thread other than the one running the loop");
    }

private:
    std::atomic<bool> m_claimed;
    std::thread::id m_thread;
};

#else

class executor_owner
{
public:
    void claim() noexcept
    {
    }

    void assert_current() const noexcept
    {
    }
};

#endif

}

#endif
