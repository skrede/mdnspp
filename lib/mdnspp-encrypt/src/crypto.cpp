#include "mdnspp/encrypt/aead.h"

#include <sodium.h>

#include <mutex>
#include <array>
#include <cstdint>

namespace mdnspp::encrypt {

void secure_zero(void *buf, std::size_t len) noexcept
{
    sodium_memzero(buf, len);
}

bool init_crypto()
{
    static std::once_flag flag;
    static bool result = false;
    std::call_once(flag, []() {
        result = (sodium_init() != -1);
    });
    return result;
}

uint64_t random_session_id() noexcept
{
    init_crypto();
    uint64_t id = 0;
    while(id == 0)
    {
        std::array<unsigned char, 8> bytes{};
        randombytes_buf(bytes.data(), bytes.size());
        for(const unsigned char byte : bytes)
            id = (id << 8) | byte;
    }
    return id;
}

}
