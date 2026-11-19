#ifndef HPP_GUARD_MDNSPP_ENCRYPT_KEY_COPY_H
#define HPP_GUARD_MDNSPP_ENCRYPT_KEY_COPY_H

#include "mdnspp/encrypt/aead.h"

#include <span>
#include <array>
#include <cstddef>
#include <cstdint>

namespace mdnspp::encrypt {

struct key_copy
{
    std::array<std::byte, 32> bytes;

    explicit key_copy(const std::array<std::byte, 32> &source)
        : bytes(source)
    {
    }

    key_copy(const key_copy &other)
        : bytes(other.bytes)
    {
    }

    key_copy &operator=(const key_copy &) = delete;

    ~key_copy()
    {
        secure_zero(bytes.data(), bytes.size());
    }

    std::span<const std::byte, 32> span() const noexcept { return bytes; }
};

struct send_key
{
    key_copy key;
    uint32_t epoch;
};

struct receive_key
{
    key_copy key;
    bool is_previous;
};

}

#endif
