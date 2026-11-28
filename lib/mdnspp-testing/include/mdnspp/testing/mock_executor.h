#ifndef HPP_GUARD_MDNSPP_TESTING_MOCK_EXECUTOR_H
#define HPP_GUARD_MDNSPP_TESTING_MOCK_EXECUTOR_H

#include "mdnspp/detail/compat.h"

#include <deque>
#include <utility>

namespace mdnspp::testing {

struct mock_executor
{
    std::deque<detail::move_only_function<void()>> m_posted;

    void drain_posted()
    {
        while (!m_posted.empty())
        {
            auto fn = std::move(m_posted.front());
            m_posted.pop_front();
            fn();
        }
    }
};

}

#endif
