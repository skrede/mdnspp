#ifndef HPP_GUARD_MDNSPP_DETAIL_SERVER_LIFECYCLE_H
#define HPP_GUARD_MDNSPP_DETAIL_SERVER_LIFECYCLE_H

#include "mdnspp/callback_types.h"

#include <atomic>
#include <utility>
#include <system_error>

namespace mdnspp::detail {

class server_lifecycle
{
public:
    server_lifecycle()
        : m_on_ready()
        , m_on_completion()
        , m_started(false)
    {
    }

    std::error_code claim_start(const std::atomic<bool> &stopped) noexcept
    {
        if(stopped.load(std::memory_order_acquire))
            return std::make_error_code(std::errc::invalid_argument);
        if(m_started.exchange(true, std::memory_order_acq_rel))
            return std::make_error_code(std::errc::operation_in_progress);
        return {};
    }

    void arm(server_completion_handler on_ready, server_completion_handler on_done)
    {
        if(on_ready)
            m_on_ready = std::move(on_ready);
        if(on_done)
            m_on_completion = std::move(on_done);
    }

    void complete_ready(std::error_code ec)
    {
        if(auto h = std::exchange(m_on_ready, nullptr); h)
            h(ec);
    }

    void complete_done(std::error_code ec)
    {
        if(auto h = std::exchange(m_on_completion, nullptr); h)
            h(ec);
    }

    void cancel()
    {
        complete_ready(std::make_error_code(std::errc::operation_canceled));
        complete_done(std::make_error_code(std::errc::operation_canceled));
    }

private:
    server_completion_handler m_on_ready;
    server_completion_handler m_on_completion;
    std::atomic<bool> m_started;
};

}

#endif
