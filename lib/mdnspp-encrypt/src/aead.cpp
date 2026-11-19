#include "mdnspp/encrypt/aead.h"
#include "mdnspp/encrypt/packet_header.h"

#include <sodium.h>

#include <algorithm>
#include <system_error>

namespace mdnspp::encrypt {

namespace {

const unsigned char *as_uchar(const std::byte *p)
{
    return reinterpret_cast<const unsigned char *>(p);
}

unsigned char *as_uchar(std::byte *p)
{
    return reinterpret_cast<unsigned char *>(p);
}

// libsodium declares its pointer parameters nonnull, so an empty span needs a stand-in address.
const unsigned char *readable(std::span<const std::byte> bytes, const unsigned char &stand_in)
{
    return bytes.empty() ? &stand_in : as_uchar(bytes.data());
}

unsigned char *writable(std::span<std::byte> bytes, unsigned char &stand_in)
{
    return bytes.empty() ? &stand_in : as_uchar(bytes.data());
}

std::size_t seal(std::span<const std::byte, 32> key, const encrypted_packet_header &hdr,
                 std::span<const std::byte> plaintext, std::span<std::byte> out)
{
    unsigned char stand_in = 0;
    unsigned long long ciphertext_len = 0;
    crypto_aead_xchacha20poly1305_ietf_encrypt(
        as_uchar(out.data() + encrypted_header_size), &ciphertext_len,
        readable(plaintext, stand_in), static_cast<unsigned long long>(plaintext.size()),
        as_uchar(out.data()), static_cast<unsigned long long>(encrypted_header_size),
        nullptr,
        as_uchar(hdr.nonce.data()), as_uchar(key.data()));
    return encrypted_header_size + static_cast<std::size_t>(ciphertext_len);
}

// The tag covers header and plaintext, both already contiguous at the front of out.
std::size_t tag_only(std::span<const std::byte, 32> key, const encrypted_packet_header &hdr,
                     std::span<const std::byte> plaintext, std::span<std::byte> out)
{
    const std::size_t body_len = encrypted_header_size + plaintext.size();
    std::copy(plaintext.begin(), plaintext.end(), out.begin() + static_cast<std::ptrdiff_t>(encrypted_header_size));

    unsigned char stand_in = 0;
    unsigned long long tag_len = 0;
    crypto_aead_xchacha20poly1305_ietf_encrypt_detached(
        &stand_in, as_uchar(out.data() + body_len), &tag_len,
        &stand_in, 0,
        as_uchar(out.data()), static_cast<unsigned long long>(body_len),
        nullptr,
        as_uchar(hdr.nonce.data()), as_uchar(key.data()));
    return body_len + encrypted_tag_size;
}

bool open_sealed(std::span<const std::byte, 32> key, const encrypted_packet_header &hdr,
                 std::span<const std::byte> packet, std::span<std::byte> out)
{
    unsigned char stand_in = 0;
    unsigned long long plaintext_len = 0;
    const int rc = crypto_aead_xchacha20poly1305_ietf_decrypt(
        writable(out, stand_in), &plaintext_len,
        nullptr,
        as_uchar(packet.data() + encrypted_header_size),
        static_cast<unsigned long long>(packet.size() - encrypted_header_size),
        as_uchar(packet.data()), static_cast<unsigned long long>(encrypted_header_size),
        as_uchar(hdr.nonce.data()), as_uchar(key.data()));
    return rc == 0;
}

bool open_tag_only(std::span<const std::byte, 32> key, const encrypted_packet_header &hdr,
                   std::span<const std::byte> packet, std::span<std::byte> out)
{
    const std::size_t body_len = packet.size() - encrypted_tag_size;
    unsigned char stand_in = 0;
    const int rc = crypto_aead_xchacha20poly1305_ietf_decrypt_detached(
        &stand_in, nullptr, &stand_in, 0,
        as_uchar(packet.data() + body_len),
        as_uchar(packet.data()), static_cast<unsigned long long>(body_len),
        as_uchar(hdr.nonce.data()), as_uchar(key.data()));
    if(rc != 0)
        return false;
    std::copy(packet.begin() + static_cast<std::ptrdiff_t>(encrypted_header_size),
              packet.begin() + static_cast<std::ptrdiff_t>(body_len), out.begin());
    return true;
}

std::error_code check_packet(std::span<const std::byte> packet, std::size_t out_size)
{
    if(packet.size() < encrypted_overhead)
        return encrypt_error::invalid_header;
    const auto hdr = deserialize_header(packet.data());
    if(hdr.magic != encrypted_magic)
        return encrypt_error::invalid_header;
    if(hdr.version != encrypted_version)
        return encrypt_error::unsupported_version;
    if(out_size < packet.size() - encrypted_overhead)
        return encrypt_error::buffer_too_small;
    return {};
}

}

std::error_code aead_encrypt(
    std::span<const std::byte, 32> key,
    const encrypted_packet_header &hdr,
    std::span<const std::byte> plaintext,
    std::span<std::byte> out,
    std::size_t &written)
{
    written = 0;
    if(!init_crypto())
        return std::make_error_code(std::errc::not_supported);
    if(out.size() < encrypted_overhead + plaintext.size())
        return encrypt_error::buffer_too_small;

    encrypted_packet_header hdr_with_nonce = hdr;
    randombytes_buf(hdr_with_nonce.nonce.data(), encrypted_nonce_size);
    const auto header_bytes = serialize_header(hdr_with_nonce);
    std::copy(header_bytes.begin(), header_bytes.end(), out.begin());

    const bool sealed = (hdr_with_nonce.flags & flag_encrypted) != 0;
    written = sealed ? seal(key, hdr_with_nonce, plaintext, out) : tag_only(key, hdr_with_nonce, plaintext, out);
    return {};
}

std::error_code aead_decrypt(
    std::span<const std::byte, 32> key,
    std::span<const std::byte> packet,
    std::span<std::byte> out,
    std::size_t &written)
{
    written = 0;
    if(!init_crypto())
        return std::make_error_code(std::errc::not_supported);
    if(const auto ec = check_packet(packet, out.size()))
        return ec;

    const auto hdr = deserialize_header(packet.data());
    const bool sealed = (hdr.flags & flag_encrypted) != 0;
    if(!(sealed ? open_sealed(key, hdr, packet, out) : open_tag_only(key, hdr, packet, out)))
        return encrypt_error::decrypt_failed;
    written = packet.size() - encrypted_overhead;
    return {};
}

}
