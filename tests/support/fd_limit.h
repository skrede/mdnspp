#ifndef HPP_GUARD_MDNSPP_SUPPORT_FD_LIMIT_H
#define HPP_GUARD_MDNSPP_SUPPORT_FD_LIMIT_H

#include <catch2/catch_test_macros.hpp>

#include <sys/resource.h>

namespace mdnspp::test_support {

class fd_limit_guard
{
public:
    explicit fd_limit_guard(rlim_t soft)
        : m_saved{}
        , m_lowered{false}
    {
        if(::getrlimit(RLIMIT_NOFILE, &m_saved) != 0 || soft >= m_saved.rlim_cur)
            return;
        rlimit lowered = m_saved;
        lowered.rlim_cur = soft;
        m_lowered = ::setrlimit(RLIMIT_NOFILE, &lowered) == 0;
    }

    ~fd_limit_guard()
    {
        if(m_lowered)
            ::setrlimit(RLIMIT_NOFILE, &m_saved);
    }

    fd_limit_guard(const fd_limit_guard &) = delete;
    fd_limit_guard &operator=(const fd_limit_guard &) = delete;

    bool lowered() const noexcept
    {
        return m_lowered;
    }

private:
    rlimit m_saved;
    bool m_lowered;
};

inline void skip_unless_lowered(const fd_limit_guard &guard)
{
    if(!guard.lowered())
        SKIP("the descriptor limit could not be lowered");
}

#if defined(__SANITIZE_ADDRESS__)
inline constexpr bool address_sanitized = true;
#elif defined(__has_feature)
#  if __has_feature(address_sanitizer)
inline constexpr bool address_sanitized = true;
#  else
inline constexpr bool address_sanitized = false;
#  endif
#else
inline constexpr bool address_sanitized = false;
#endif

// The lowered limit also makes the sanitizer's own pipe() fail, which ends the process in the middle of the case.
inline void skip_under_address_sanitizer()
{
    if constexpr(address_sanitized)
        SKIP("AddressSanitizer needs spare descriptors for its own pipe() under the lowered limit");
}

}

#endif
