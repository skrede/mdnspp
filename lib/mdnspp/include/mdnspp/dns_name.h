#ifndef HPP_GUARD_MDNSPP_DNS_NAME_H
#define HPP_GUARD_MDNSPP_DNS_NAME_H

#include "mdnspp/mdns_error.h"

#include "mdnspp/detail/compat.h"

#include <string>
#include <vector>
#include <compare>
#include <cstddef>
#include <cstdint>
#include <ostream>
#include <algorithm>
#include <string_view>

namespace mdnspp {
namespace detail {

// RFC 1035 §5.1 presentation-format escape handling, shared by dns_name and
// the wire codec (detail/dns_read.h).
//
// Canonical escaped form: within a label, '.' is written "\." and '\' is
// written "\\"; bytes below 0x20 and the byte 0x7F are written "\DDD" (three
// decimal digits). All other bytes — including UTF-8 sequences at and above
// 0x80 — are written verbatim with their original case (RFC 6763 §4.1:
// instance names are user-facing UTF-8 and must not be altered).
inline void append_escaped_label_byte(std::string &out, char c)
{
    auto b = static_cast<uint8_t>(c);
    if(c == '.' || c == '\\')
    {
        out.push_back('\\');
        out.push_back(c);
    }
    else if(b < 0x20 || b == 0x7F)
    {
        out.push_back('\\');
        out.push_back(static_cast<char>('0' + b / 100));
        out.push_back(static_cast<char>('0' + (b / 10) % 10));
        out.push_back(static_cast<char>('0' + b % 10));
    }
    else
    {
        out.push_back(c);
    }
}

// Splits a presentation-format name into its unescaped label byte strings.
// Recognizes the RFC 1035 §5.1 escapes "\X" (literal X) and "\DDD" (byte
// value, exactly three decimal digits, at most 255). Enforces the §2.3.4
// limits on the unescaped bytes: 1-63 octets per label and 255 octets total
// wire length (length prefixes plus root terminator). Empty labels ("a..b"),
// dangling escapes and malformed "\DDD" escapes are errors. "" and "." both
// denote the root name (zero labels).
inline expected<std::vector<std::string>, mdns_error>
parse_presentation_labels(std::string_view name)
{
    std::vector<std::string> labels;
    if(name.empty() || name == ".")
        return labels;

    std::string current;
    std::size_t wire_length = 1; // root terminator

    auto flush_label = [&]() -> bool
    {
        if(current.empty() || current.size() > 63)
            return false;
        wire_length += 1 + current.size();
        labels.push_back(std::move(current));
        current.clear();
        return true;
    };

    for(std::size_t i = 0; i < name.size();)
    {
        char c = name[i];
        if(c == '\\')
        {
            if(i + 1 >= name.size())
                return make_unexpected(mdns_error::invalid_name);
            char next = name[i + 1];
            if(next >= '0' && next <= '9')
            {
                if(i + 3 >= name.size()
                   || name[i + 2] < '0' || name[i + 2] > '9'
                   || name[i + 3] < '0' || name[i + 3] > '9')
                    return make_unexpected(mdns_error::invalid_name);
                uint32_t value = static_cast<uint32_t>(next - '0') * 100
                    + static_cast<uint32_t>(name[i + 2] - '0') * 10
                    + static_cast<uint32_t>(name[i + 3] - '0');
                if(value > 255)
                    return make_unexpected(mdns_error::invalid_name);
                current.push_back(static_cast<char>(static_cast<uint8_t>(value)));
                i += 4;
            }
            else
            {
                current.push_back(next);
                i += 2;
            }
        }
        else if(c == '.')
        {
            if(!flush_label())
                return make_unexpected(mdns_error::invalid_name);
            ++i;
        }
        else
        {
            current.push_back(c);
            ++i;
        }
    }

    if(!current.empty() && !flush_label())
        return make_unexpected(mdns_error::invalid_name);

    if(wire_length > 255)
        return make_unexpected(mdns_error::invalid_name);

    return labels;
}

// Joins unescaped labels into the canonical escaped presentation form with a
// trailing dot. The root name (zero labels) yields an empty string.
inline std::string make_canonical_presentation(const std::vector<std::string> &labels)
{
    std::string out;
    for(const auto &label : labels)
    {
        for(char c : label)
            append_escaped_label_byte(out, c);
        out.push_back('.');
    }
    return out;
}

}

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
            return detail::make_unexpected(labels.error());
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
