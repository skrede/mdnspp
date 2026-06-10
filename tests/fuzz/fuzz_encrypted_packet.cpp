#include "mdnspp/encrypt/aead.h"

#include <span>
#include <array>
#include <cstddef>
#include <cstdint>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    static const bool crypto_ok = mdnspp::encrypt::init_crypto();
    (void)crypto_ok;

    std::array<std::byte, 32> key{};
    key.fill(std::byte{0x42});

    auto result = mdnspp::encrypt::aead_decrypt(
        std::span<const std::byte, 32>(key),
        std::span<const std::byte>(reinterpret_cast<const std::byte *>(data), size));
    (void)result;
    return 0;
}
