#ifndef HPP_GUARD_MDNSPP_ENCRYPT_SECURE_KEY_H
#define HPP_GUARD_MDNSPP_ENCRYPT_SECURE_KEY_H

#include <span>
#include <array>
#include <cstddef>

namespace mdnspp {

class secure_key
{
public:
    static constexpr std::size_t key_size = 32;

    secure_key() = default;
    explicit secure_key(std::array<std::byte, key_size> key) noexcept;

    secure_key(const secure_key &) = delete;
    secure_key &operator=(const secure_key &) = delete;
    secure_key(secure_key &&other) noexcept;
    secure_key &operator=(secure_key &&other) noexcept;

    ~secure_key();

    std::span<const std::byte, key_size> bytes() const noexcept;

private:
    std::array<std::byte, key_size> m_key{};
};

}

#endif
