#include "mdnspp/encrypt/aead.h"

#include <sodium.h>

#include <mutex>
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

uint64_t random_sequence_start() noexcept
{
    init_crypto();
    uint32_t high = 0;
    randombytes_buf(&high, 3);
    return static_cast<uint64_t>(high & 0x00FFFFFFu) << 40;
}

}
