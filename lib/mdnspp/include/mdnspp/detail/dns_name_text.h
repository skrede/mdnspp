#ifndef HPP_GUARD_MDNSPP_DETAIL_DNS_NAME_TEXT_H
#define HPP_GUARD_MDNSPP_DETAIL_DNS_NAME_TEXT_H

#include "mdnspp/detail/compat.h"

#include "mdnspp/mdns_error.h"

#include <string>
#include <vector>
#include <cstddef>
#include <cstdint>
#include <string_view>

namespace mdnspp::detail {

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

inline bool is_decimal_digit(char c)
{
    return c >= '0' && c <= '9';
}

struct label_accumulator
{
    std::vector<std::string> labels;
    std::string current;
    std::size_t wire_length;

    label_accumulator()
        : wire_length(1) // root terminator
    {}

    bool flush()
    {
        if(current.empty() || current.size() > 63)
            return false;
        wire_length += 1 + current.size();
        labels.push_back(std::move(current));
        current.clear();
        return true;
    }
};

// Decodes the escape at name[i] == '\\' ("\X" literal X, or "\DDD" with
// exactly three decimal digits, at most 255), appends the byte to current and
// advances i past it. Returns false on a dangling or malformed escape.
inline bool decode_escape(std::string_view name, std::size_t &i, std::string &current)
{
    if(i + 1 >= name.size())
        return false;
    char next = name[i + 1];
    if(!is_decimal_digit(next))
    {
        current.push_back(next);
        i += 2;
        return true;
    }
    if(i + 3 >= name.size() || !is_decimal_digit(name[i + 2]) || !is_decimal_digit(name[i + 3]))
        return false;
    uint32_t value = static_cast<uint32_t>(next - '0') * 100
        + static_cast<uint32_t>(name[i + 2] - '0') * 10
        + static_cast<uint32_t>(name[i + 3] - '0');
    if(value > 255)
        return false;
    current.push_back(static_cast<char>(static_cast<uint8_t>(value)));
    i += 4;
    return true;
}

inline bool consume_presentation_char(std::string_view name, std::size_t &i, label_accumulator &acc)
{
    char c = name[i];
    if(c == '\\')
        return decode_escape(name, i, acc.current);
    if(c == '.')
    {
        ++i;
        return acc.flush();
    }
    acc.current.push_back(c);
    ++i;
    return true;
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
    if(name.empty() || name == ".")
        return std::vector<std::string>{};

    label_accumulator acc;
    for(std::size_t i = 0; i < name.size();)
    {
        if(!consume_presentation_char(name, i, acc))
            return unexpected(mdns_error::invalid_name);
    }

    if(!acc.current.empty() && !acc.flush())
        return unexpected(mdns_error::invalid_name);

    if(acc.wire_length > 255)
        return unexpected(mdns_error::invalid_name);

    return std::move(acc.labels);
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

#endif
