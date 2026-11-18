#ifndef HPP_GUARD_MDNSPP_DETAIL_BAD_EXPECTED_ACCESS_H
#define HPP_GUARD_MDNSPP_DETAIL_BAD_EXPECTED_ACCESS_H

#include <utility>
#include <exception>

namespace mdnspp::detail {

template <typename E>
class bad_expected_access;

template <>
class bad_expected_access<void> : public std::exception
{
public:
    const char *what() const noexcept override { return "bad access to an expected that holds an error"; }

protected:
    bad_expected_access() noexcept = default;
    bad_expected_access(const bad_expected_access &) noexcept = default;
    bad_expected_access(bad_expected_access &&) noexcept = default;
    bad_expected_access &operator=(const bad_expected_access &) noexcept = default;
    bad_expected_access &operator=(bad_expected_access &&) noexcept = default;
    ~bad_expected_access() override = default;
};

template <typename E>
class bad_expected_access : public bad_expected_access<void>
{
public:
    explicit bad_expected_access(E e) : m_error(std::move(e))
    {
    }

    const E &error() const & noexcept { return m_error; }
    E &error() & noexcept { return m_error; }
    const E &&error() const && noexcept { return std::move(m_error); }
    E &&error() && noexcept { return std::move(m_error); }

private:
    E m_error;
};

}

#endif
