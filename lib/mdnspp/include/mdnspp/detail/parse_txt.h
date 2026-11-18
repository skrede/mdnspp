#ifndef HPP_GUARD_MDNSPP_DETAIL_PARSE_TXT_H
#define HPP_GUARD_MDNSPP_DETAIL_PARSE_TXT_H

#include "mdnspp/records.h"

#include <span>
#include <vector>
#include <cstddef>
#include <cstdint>
#include <string_view>

namespace mdnspp::parse {

inline service_txt split_txt_entry(std::string_view entry_sv)
{
    service_txt kv;
    if(auto sep = entry_sv.find('='); sep != std::string_view::npos)
    {
        kv.key = std::string(entry_sv.substr(0, sep));
        kv.value = std::string(entry_sv.substr(sep + 1));
    }
    else
    {
        kv.key = std::string(entry_sv);
    }
    return kv;
}

// Walks the length-prefixed strings of TXT rdata in [pos, end). A string that
// overruns end stops the walk silently. RFC 6763 §6.4: a zero-length string
// (including the canonical empty TXT record, a single 0x00 byte) is ignored,
// as is a string starting with '=' (no key).
inline std::vector<service_txt> parse_txt_entries(std::span<const std::byte> buffer, size_t pos, size_t end)
{
    std::vector<service_txt> entries;

    while(pos < end)
    {
        uint8_t entry_len = static_cast<uint8_t>(buffer[pos]);
        ++pos;

        if(pos + entry_len > end)
            break;

        if(entry_len == 0)
            continue;

        if(static_cast<char>(static_cast<uint8_t>(buffer[pos])) != '=')
            entries.push_back(split_txt_entry(std::string_view(
                reinterpret_cast<const char *>(buffer.data() + pos), entry_len)));
        pos += entry_len;
    }

    return entries;
}

}

#endif
