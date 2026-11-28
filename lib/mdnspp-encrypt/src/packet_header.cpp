#include "mdnspp/encrypt/packet_header.h"

#include "mdnspp/detail/byte_order.h"

#include <algorithm>

namespace mdnspp::encrypt {

std::array<std::byte, encrypted_header_size> serialize_header(const encrypted_packet_header &hdr)
{
    std::array<std::byte, encrypted_header_size> buf{};
    std::byte *p = buf.data();

    detail::write_u16_be(p, hdr.magic);       p += 2;
    *p++ = static_cast<std::byte>(hdr.version);
    *p++ = static_cast<std::byte>(hdr.flags);
    detail::write_u32_be(p, hdr.sender_id);   p += 4;
    detail::write_u64_be(p, hdr.session_id);  p += 8;
    detail::write_u64_be(p, hdr.sequence);    p += 8;
    detail::write_u32_be(p, hdr.epoch);       p += 4;
    std::copy(hdr.nonce.begin(), hdr.nonce.end(), p);

    return buf;
}

encrypted_packet_header deserialize_header(const std::byte *buf)
{
    encrypted_packet_header hdr;
    const std::byte *p = buf;

    hdr.magic      = detail::read_u16_be(p);  p += 2;
    hdr.version    = static_cast<uint8_t>(*p++);
    hdr.flags      = static_cast<uint8_t>(*p++);
    hdr.sender_id  = detail::read_u32_be(p);  p += 4;
    hdr.session_id = detail::read_u64_be(p);  p += 8;
    hdr.sequence   = detail::read_u64_be(p);  p += 8;
    hdr.epoch      = detail::read_u32_be(p);  p += 4;

    std::copy(p, p + encrypted_nonce_size, hdr.nonce.begin());

    return hdr;
}

}
