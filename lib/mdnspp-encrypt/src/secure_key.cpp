#include "mdnspp/encrypt/secure_key.h"

#include <sodium.h>

namespace mdnspp::encrypt {

secure_key::secure_key() noexcept
    : m_key{}
{
}

secure_key::secure_key(const std::array<std::byte, key_size> &key) noexcept
    : m_key(key)
{
}

secure_key::secure_key(secure_key &&other) noexcept
    : m_key(other.m_key)
{
    sodium_memzero(other.m_key.data(), key_size);
}

secure_key &secure_key::operator=(secure_key &&other) noexcept
{
    if(this != &other)
    {
        sodium_memzero(m_key.data(), key_size);
        m_key = other.m_key;
        sodium_memzero(other.m_key.data(), key_size);
    }
    return *this;
}

secure_key::~secure_key()
{
    sodium_memzero(m_key.data(), key_size);
}

std::span<const std::byte, secure_key::key_size> secure_key::bytes() const noexcept
{
    return m_key;
}

}
