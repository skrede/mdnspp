#ifndef HPP_GUARD_MDNSPP_DNS_NAME_H
#define HPP_GUARD_MDNSPP_DNS_NAME_H

#include <string>
#include <compare>
#include <cctype>
#include <cstddef>
#include <ostream>
#include <string_view>

namespace mdnspp {

// dns_name — normalized DNS fully-qualified domain name.
//
// Invariant: the stored value is always lowercase with a trailing dot, or empty
// (representing the DNS root label, which has no trailing dot by convention).
// Normalization follows RFC 1035 §3.1 (labels are case-insensitive).
//
// Modelled after std::filesystem::path: non-explicit construction normalizes
// on entry, implicit conversion to std::string_view exposes the canonical form.
// This makes dns_name transparent at all call sites — no explicit casts needed.
//
// Internal storage: std::string. SSO covers typical mDNS names (~30 chars) on
// all major implementations, so no custom small-buffer optimization is needed.
//
// Label-length validation (RFC 1035 §2.3.4: 63-octet label, 253-octet name) is
// deliberately absent from the constructor. Validation at the wire boundary
// (read_dns_name / encode_dns_name) is the right layer; imposing it here would
// force throwing constructors and break the path-like ergonomics.
class dns_name
{
public:
    // Non-explicit: mirrors std::filesystem::path implicit construction from a
    // string-like value. Normalizes the input to lowercase FQDN on entry.
    dns_name(std::string_view name) // NOLINT(google-explicit-constructor)
        : m_name(normalize(name))
    {}

    dns_name() = default;

    dns_name &operator=(std::string_view name) // NOLINT(google-explicit-constructor)
    {
        m_name = normalize(name);
        return *this;
    }

    // Transparent, zero-cost view of the normalized value. Non-explicit so that
    // dns_name is accepted wherever std::string_view is expected.
    operator std::string_view() const noexcept { return m_name; } // NOLINT(google-explicit-constructor)

    // Access as std::string for APIs that require a std::string key (e.g. maps
    // that cannot accept string_view for heterogeneous lookup).
    const std::string &str() const noexcept { return m_name; }

    bool empty() const noexcept { return m_name.empty(); }

    bool operator==(const dns_name &) const = default;
    auto operator<=>(const dns_name &) const = default;

private:
    // Returns the lowercase FQDN of sv, or empty string if sv is empty.
    // Appends '.' when the last character is not already '.'.
    static std::string normalize(std::string_view sv)
    {
        if (sv.empty())
            return {};

        std::string result;
        result.reserve(sv.size() + 1);
        for (unsigned char c : sv)
            result.push_back(static_cast<char>(std::tolower(c)));

        if (result.back() != '.')
            result.push_back('.');

        return result;
    }

    std::string m_name;
};

template <typename CharT, typename Traits>
std::basic_ostream<CharT, Traits> &operator<<(std::basic_ostream<CharT, Traits> &os,
                                               const dns_name &n)
{
    return os << static_cast<std::string_view>(n);
}

}

template <>
struct std::hash<mdnspp::dns_name>
{
    std::size_t operator()(const mdnspp::dns_name &n) const noexcept
    {
        return std::hash<std::string_view>{}(static_cast<std::string_view>(n));
    }
};

#endif
