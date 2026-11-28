#ifndef HPP_GUARD_MDNSPP_FUZZ_FUZZ_INPUT_H
#define HPP_GUARD_MDNSPP_FUZZ_FUZZ_INPUT_H

#include <vector>
#include <cstddef>
#include <cstdint>
#include <cstring>

namespace mdnspp::fuzz {

class input_reader
{
public:
    input_reader(const uint8_t *data, std::size_t size) noexcept
        : m_data(data), m_size(size), m_pos(0)
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
        const uint16_t high = u8();
        const uint16_t low = u8();
        return static_cast<uint16_t>(high << 8 | low);
    }

    uint32_t u32() noexcept
    {
        const uint32_t high = u16();
        const uint32_t low = u16();
        return high << 16 | low;
    }

    std::vector<std::byte> remaining_bytes(std::size_t cap) noexcept
    {
        const std::size_t available = m_size - m_pos;
        const std::size_t n = available < cap ? available : cap;
        std::vector<std::byte> out(n);
        if(n > 0)
            std::memcpy(out.data(), m_data + m_pos, n);
        m_pos += n;
        return out;
    }

    std::size_t left() const noexcept
    {
        return m_size - m_pos;
    }

private:
    const uint8_t *m_data;
    std::size_t m_size;
    std::size_t m_pos;
};

}

#endif
