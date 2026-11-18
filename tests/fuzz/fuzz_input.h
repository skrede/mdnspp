#ifndef HPP_GUARD_MDNSPP_FUZZ_FUZZ_INPUT_H
#define HPP_GUARD_MDNSPP_FUZZ_FUZZ_INPUT_H

#include <vector>
#include <cstddef>
#include <cstdint>
#include <cstring>

namespace mdnspp::fuzz {

// Sequential consumer over the fuzz input.
class input_reader
{
public:
    input_reader(const uint8_t *data, size_t size) noexcept
        : m_data(data), m_size(size)
    {
    }

    uint8_t u8() noexcept
    {
        if(m_pos >= m_size)
            return 0;
        return m_data[m_pos++];
    }

    uint16_t u16() noexcept
    {
        return static_cast<uint16_t>(static_cast<uint16_t>(u8()) << 8 | u8());
    }

    uint32_t u32() noexcept
    {
        return static_cast<uint32_t>(u16()) << 16 | u16();
    }

    std::vector<std::byte> remaining_bytes(size_t cap) noexcept
    {
        const size_t available = m_size - m_pos;
        const size_t n = available < cap ? available : cap;
        std::vector<std::byte> out(n);
        if(n > 0)
            std::memcpy(out.data(), m_data + m_pos, n);
        m_pos += n;
        return out;
    }

    size_t left() const noexcept
    {
        return m_size - m_pos;
    }

private:
    const uint8_t *m_data;
    size_t m_size;
    size_t m_pos{0};
};

}

#endif
