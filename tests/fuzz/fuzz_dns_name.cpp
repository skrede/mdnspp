#include "mdnspp/dns_name.h"

#include <cassert>
#include <cctype>
#include <cstddef>
#include <cstdint>
#include <string_view>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    std::string_view input(reinterpret_cast<const char *>(data), size);

    try
    {
        mdnspp::dns_name name(input);

        if(!name.empty())
        {
            // Trailing dot invariant
            assert(name.str().back() == '.');

            // Lowercase normalization invariant
            for(char c : name.str())
            {
                if(std::isalpha(static_cast<unsigned char>(c)))
                    assert(std::islower(static_cast<unsigned char>(c)));
            }
        }
    }
    catch(...)
    {
        // dns_name may throw on invalid input — that is correct behavior
    }

    return 0;
}
