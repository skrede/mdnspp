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

// dns_name — DNS fully-qualified domain name in canonical presentation form.
//
// Invariant: the stored value is the RFC 1035 §5.1 escaped presentation form
// with a trailing dot and the original byte case, or empty (the DNS root
// name; also the result of normalizing invalid input). Within a label, '.'
// is stored as "\." and '\' as "\\"; bytes below 0x20 and 0x7F as "\DDD";
// all other bytes — including UTF-8 sequences at and above 0x80 — verbatim.
// Case is preserved end-to-end for transmission (RFC 6763 §4.1: instance
// names are user-facing UTF-8), so an escaped dot inside a label ("Dr\.
// Smith._http._tcp.local.") never collides with a label separator.
//
// Comparison, ordering and hashing are case-insensitive over ASCII 'A'-'Z'
// only (RFC 6762 §16); bytes at and above 0x80 are never folded. Because
// both operands hold the canonical escaped form, a per-byte folded compare
// is exactly label-aware case-insensitive name comparison.
//
// Construction from a presentation string validates the §5.1 escapes and the
// §2.3.4 limits (63-octet label, 255-octet wire name, measured on the
// unescaped bytes). The implicit constructors normalize invalid input to the
// empty name; parse() is the checked path and reports
// mdns_error::invalid_name.
//
// Modelled after std::filesystem::path: non-explicit construction normalizes
// on entry, implicit conversion to std::string_view exposes the canonical
// form. This makes dns_name transparent at all call sites.
class dns_name
{
public:
    // Non-explicit: mirrors std::filesystem::path implicit construction from a
    // string-like value. Normalizes to canonical escaped FQDN form on entry;
    // invalid input normalizes to the empty name (use parse() to detect it).
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

    // Checked construction: returns mdns_error::invalid_name instead of
    // normalizing invalid input to the empty name.
    static expected<dns_name, mdns_error> parse(std::string_view name)
    {
        auto labels = detail::parse_presentation_labels(name);
        if(!labels.has_value())
            return detail::unexpected(labels.error());
        dns_name result;
        result.m_name = detail::make_canonical_presentation(*labels);
        return result;
    }

    // Transparent, zero-cost view of the canonical value. Non-explicit so that
    // dns_name is accepted wherever std::string_view is expected.
    operator std::string_view() const noexcept { return m_name; } // NOLINT(google-explicit-constructor)

    // Access as std::string for APIs that require a std::string key (e.g. maps
    // that cannot accept string_view for heterogeneous lookup).
    const std::string &str() const noexcept { return m_name; }

    bool empty() const noexcept { return m_name.empty(); }
    auto find(std::string_view sv, std::size_t pos = 0) const noexcept { return m_name.find(sv, pos); }
    static constexpr auto npos = std::string::npos;

    // RFC 6762 §16 comparison folding: ASCII 'A'-'Z' to 'a'-'z' only; never
    // touches bytes at and above 0x80 (UTF-8 label bytes).
    static constexpr char ascii_fold(char c) noexcept
    {
        return (c >= 'A' && c <= 'Z') ? static_cast<char>(c - 'A' + 'a') : c;
    }

    // ASCII-lowercased canonical presentation form: the single normalization
    // to use where a std::string key must match dns_name equality semantics.
    std::string comparison_key() const
    {
        std::string key(m_name);
        for(char &c : key)
            c = ascii_fold(c);
        return key;
    }

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
    // Returns the canonical escaped presentation FQDN of sv (original case,
    // trailing dot), or an empty string when sv is empty, the root name "."
    // or invalid presentation input.
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
