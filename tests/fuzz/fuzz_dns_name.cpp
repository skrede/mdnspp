#include "mdnspp/dns_name.h"

#include <cassert>
#include <cstddef>
#include <cstdint>
#include <string_view>

namespace {

void check_canonical_form(const mdnspp::dns_name &name)
{
    // Trailing dot invariant of the canonical escaped presentation form
    assert(name.str().back() == '.');

    // The canonical form must itself be valid presentation input
    auto reparsed = mdnspp::dns_name::parse(name.str());
    assert(reparsed.has_value());

    // Case-insensitive self-equality and hash consistency
    assert(name == *reparsed);
    assert(std::hash<mdnspp::dns_name>{}(name) == std::hash<mdnspp::dns_name>{}(*reparsed));

    // comparison_key is the ASCII-folded canonical form, so it has the canonical form's length
    assert(name.comparison_key().size() == name.str().size());
}

void check_parse_agrees(std::string_view input, const mdnspp::dns_name &name)
{
    // parse() succeeds exactly when normalization did not collapse non-root input
    auto checked = mdnspp::dns_name::parse(input);
    if(checked.has_value())
        assert(checked->str() == name.str());
    else
        assert(name.empty());
}

}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    std::string_view input(reinterpret_cast<const char *>(data), size);

    mdnspp::dns_name name(input);

    if(!name.empty())
        check_canonical_form(name);

    check_parse_agrees(input, name);

    return 0;
}
