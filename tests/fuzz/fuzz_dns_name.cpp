#include "mdnspp/dns_name.h"

#include <cassert>
#include <cstddef>
#include <cstdint>
#include <string_view>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    std::string_view input(reinterpret_cast<const char *>(data), size);

    mdnspp::dns_name name(input);

    if(!name.empty())
    {
        // Trailing dot invariant of the canonical escaped presentation form
        assert(name.str().back() == '.');

        // The canonical form must itself be valid presentation input
        auto reparsed = mdnspp::dns_name::parse(name.str());
        assert(reparsed.has_value());

        // Case-insensitive self-equality and hash consistency
        assert(name == *reparsed);
        assert(std::hash<mdnspp::dns_name>{}(name) == std::hash<mdnspp::dns_name>{}(*reparsed));

        // comparison_key is the ASCII-folded canonical form: same length as
        // the canonical form, equal for any case variant of the same name
        assert(name.comparison_key().size() == name.str().size());
    }

    // The checked path agrees with the normalizing constructors: parse()
    // succeeds exactly when normalization did not collapse non-root input
    auto checked = mdnspp::dns_name::parse(input);
    if(checked.has_value())
        assert(checked->str() == name.str());
    else
        assert(name.empty());

    return 0;
}
