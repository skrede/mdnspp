#ifndef HPP_GUARD_MDNSPP_DNS_NAME_H
#define HPP_GUARD_MDNSPP_DNS_NAME_H

#include "mdnspp/mdns_error.h"

#include "mdnspp/detail/compat.h"
#include "mdnspp/detail/dns_name_text.h"

#include <string>
#include <vector>
#include <compare>
#include <cstddef>
#include <cstdint>
#include <ostream>
#include <algorithm>
#include <string_view>

namespace mdnspp {

class dns_name
{
public:
    dns_name(std::string_view name) // NOLINT(google-explicit-constructor)
        : m_name(normalize(name))
    {}

    dns_name(const char *name) // NOLINT(google-explicit-constructor)
        : m_name(normalize(std::string_view{name}))
    {}

    dns_name(const std::string &name) // NOLINT(google-explicit-constructor)
        : m_name(normalize(name))
    {}

    dns_name(std::string &&name) // NOLINT(google-explicit-constructor)
        : m_name(normalize(std::string_view{name}))
    {}

    dns_name() = default;

    dns_name &operator=(std::string_view name)
    {
        m_name = normalize(name);
        return *this;
    }

    dns_name &operator=(const char *name)
    {
        m_name = normalize(std::string_view{name});
        return *this;
    }

    dns_name &operator=(const std::string &name)
    {
        m_name = normalize(name);
        return *this;
    }

    dns_name &operator=(std::string &&name)
    {
        m_name = normalize(std::string_view{name});
        return *this;
    }

    static expected<dns_name, mdns_error> parse(std::string_view name)
    {
        auto labels = detail::parse_presentation_labels(name);
        if(!labels.has_value())
            return detail::unexpected(labels.error());
        dns_name result;
        result.m_name = detail::make_canonical_presentation(*labels);
        return result;
    }

    operator std::string_view() const noexcept { return m_name; } // NOLINT(google-explicit-constructor)

    const std::string &str() const noexcept { return m_name; }

    bool empty() const noexcept { return m_name.empty(); }
    auto find(std::string_view sv, std::size_t pos = 0) const noexcept { return m_name.find(sv, pos); }
    static constexpr auto npos = std::string::npos;

    // RFC 6762 §16: only ASCII 'A'-'Z' fold; UTF-8 bytes at and above 0x80 never do.
    static constexpr char ascii_fold(char c) noexcept
    {
        return (c >= 'A' && c <= 'Z') ? static_cast<char>(c - 'A' + 'a') : c;
    }

    std::string comparison_key() const
    {
        std::string key(m_name);
        for(char &c : key)
            c = ascii_fold(c);
        return key;
    }

    // Both operands hold the canonical escaped form, so a per-byte folded compare is label-aware: an escaped
    // dot inside a label never matches a separator.
    bool operator==(const dns_name &other) const noexcept
    {
        return m_name.size() == other.m_name.size()
            && std::equal(m_name.begin(), m_name.end(), other.m_name.begin(),
                          [](char a, char b) { return ascii_fold(a) == ascii_fold(b); });
    }

    std::strong_ordering operator<=>(const dns_name &other) const noexcept
    {
        return std::lexicographical_compare_three_way(
            m_name.begin(), m_name.end(), other.m_name.begin(), other.m_name.end(),
            [](char a, char b) { return ascii_fold(a) <=> ascii_fold(b); });
    }

private:
    static std::string normalize(std::string_view sv)
    {
        auto labels = detail::parse_presentation_labels(sv);
        if(!labels.has_value())
            return {};
        return detail::make_canonical_presentation(*labels);
    }

    std::string m_name;
};

inline std::ostream &operator<<(std::ostream &os, const dns_name &n)
{
    return os << static_cast<std::string_view>(n);
}

}

template <>
struct std::hash<mdnspp::dns_name>
{
    std::size_t operator()(const mdnspp::dns_name &n) const noexcept
    {
        // FNV-1a over ASCII-folded bytes so that names differing only in
        // ASCII case hash equal, matching dns_name::operator==.
        uint64_t h = 14695981039346656037ull;
        for(char c : static_cast<std::string_view>(n))
        {
            h ^= static_cast<uint8_t>(mdnspp::dns_name::ascii_fold(c));
            h *= 1099511628211ull;
        }
        return static_cast<std::size_t>(h);
    }
};

#endif
