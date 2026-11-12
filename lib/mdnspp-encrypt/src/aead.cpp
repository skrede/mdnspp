#include "mdnspp/encrypt/aead.h"
#include "mdnspp/encrypt/packet_header.h"

#include <sodium.h>

#include <array>
#include <vector>
#include <algorithm>

namespace mdnspp::encrypt {

namespace {

using header_buffer = std::array<std::byte, encrypted_header_size>;

const unsigned char *as_uchar(const std::byte *p)
{
    return reinterpret_cast<const unsigned char *>(p);
}

unsigned char *as_uchar(std::byte *p)
{
    return reinterpret_cast<unsigned char *>(p);
}

std::vector<unsigned char> build_aad(const header_buffer &header_bytes, std::span<const std::byte> payload)
{
    std::vector<unsigned char> aad;
    aad.resize(encrypted_header_size + payload.size());
    std::copy(header_bytes.begin(), header_bytes.end(),
              reinterpret_cast<std::byte *>(aad.data()));
    std::copy(payload.begin(), payload.end(),
              reinterpret_cast<std::byte *>(aad.data() + encrypted_header_size));
    return aad;
}

std::vector<std::byte> encrypt_sealed(
    std::span<const std::byte, 32> key,
    const encrypted_packet_header &hdr,
    const header_buffer &header_bytes,
    std::span<const std::byte> plaintext)
{
    const std::size_t ciphertext_len = plaintext.size() + crypto_aead_xchacha20poly1305_ietf_ABYTES;
    std::vector<std::byte> output(encrypted_header_size + ciphertext_len);
    std::copy(header_bytes.begin(), header_bytes.end(), output.begin());

    unsigned long long actual_ciphertext_len = 0;
    crypto_aead_xchacha20poly1305_ietf_encrypt(
        as_uchar(output.data() + encrypted_header_size), &actual_ciphertext_len,
        as_uchar(plaintext.data()), static_cast<unsigned long long>(plaintext.size()),
        as_uchar(header_bytes.data()), static_cast<unsigned long long>(encrypted_header_size),
        nullptr,
        as_uchar(hdr.nonce.data()), as_uchar(key.data()));

    output.resize(encrypted_header_size + actual_ciphertext_len);
    return output;
}

std::vector<std::byte> encrypt_authenticated(
    std::span<const std::byte, 32> key,
    const encrypted_packet_header &hdr,
    const header_buffer &header_bytes,
    std::span<const std::byte> plaintext)
{
    std::vector<std::byte> output(encrypted_header_size + plaintext.size() + encrypted_tag_size);
    std::copy(header_bytes.begin(), header_bytes.end(), output.begin());
    std::copy(plaintext.begin(), plaintext.end(),
              output.begin() + static_cast<std::ptrdiff_t>(encrypted_header_size));

    const auto aad = build_aad(header_bytes, plaintext);
    unsigned long long tag_len = 0;

    // Zero-length message: the tag covers only the AAD (header + plaintext).
    // libsodium's nonnull attributes still require valid pointers.
    unsigned char dummy = 0;
    crypto_aead_xchacha20poly1305_ietf_encrypt_detached(
        &dummy, as_uchar(output.data() + encrypted_header_size + plaintext.size()), &tag_len,
        &dummy, 0,
        aad.data(), static_cast<unsigned long long>(aad.size()),
        nullptr,
        as_uchar(hdr.nonce.data()), as_uchar(key.data()));

    return output;
}

detail::expected<std::vector<std::byte>, encrypt_error> decrypt_sealed(
    std::span<const std::byte, 32> key,
    const encrypted_packet_header &hdr,
    const header_buffer &header_bytes,
    std::span<const std::byte> packet)
{
    const std::byte *ciphertext_ptr = packet.data() + encrypted_header_size;
    const std::size_t ciphertext_len = packet.size() - encrypted_header_size;

    std::vector<std::byte> plaintext(ciphertext_len - crypto_aead_xchacha20poly1305_ietf_ABYTES);
    unsigned long long plaintext_len = 0;

    int rc = crypto_aead_xchacha20poly1305_ietf_decrypt(
        as_uchar(plaintext.data()), &plaintext_len,
        nullptr,
        as_uchar(ciphertext_ptr), static_cast<unsigned long long>(ciphertext_len),
        as_uchar(header_bytes.data()), static_cast<unsigned long long>(encrypted_header_size),
        as_uchar(hdr.nonce.data()), as_uchar(key.data()));

    if(rc != 0)
        return detail::make_unexpected(encrypt_error::decrypt_failed);

    plaintext.resize(plaintext_len);
    return plaintext;
}

detail::expected<std::vector<std::byte>, encrypt_error> decrypt_authenticated(
    std::span<const std::byte, 32> key,
    const encrypted_packet_header &hdr,
    const header_buffer &header_bytes,
    std::span<const std::byte> packet)
{
    const std::size_t payload_len = packet.size() - encrypted_header_size - encrypted_tag_size;
    const std::byte *payload_ptr = packet.data() + encrypted_header_size;
    const std::byte *tag_ptr = packet.data() + packet.size() - encrypted_tag_size;

    const auto aad = build_aad(header_bytes, std::span<const std::byte>(payload_ptr, payload_len));

    // Zero-length ciphertext: libsodium's nonnull attributes still require valid pointers.
    unsigned char dummy = 0;
    int rc = crypto_aead_xchacha20poly1305_ietf_decrypt_detached(
        &dummy, nullptr, &dummy, 0,
        as_uchar(tag_ptr),
        aad.data(), static_cast<unsigned long long>(aad.size()),
        as_uchar(hdr.nonce.data()), as_uchar(key.data()));

    if(rc != 0)
        return detail::make_unexpected(encrypt_error::decrypt_failed);

    return std::vector<std::byte>(payload_ptr, payload_ptr + payload_len);
}

}

std::vector<std::byte> aead_encrypt(
    std::span<const std::byte, 32> key,
    const encrypted_packet_header &hdr,
    std::span<const std::byte> plaintext)
{
    init_crypto();

    encrypted_packet_header hdr_with_nonce = hdr;
    randombytes_buf(hdr_with_nonce.nonce.data(), encrypted_nonce_size);

    const auto header_bytes = serialize_header(hdr_with_nonce);

    if((hdr_with_nonce.flags & flag_encrypted) != 0)
        return encrypt_sealed(key, hdr_with_nonce, header_bytes, plaintext);
    return encrypt_authenticated(key, hdr_with_nonce, header_bytes, plaintext);
}

detail::expected<std::vector<std::byte>, encrypt_error> aead_decrypt(
    std::span<const std::byte, 32> key,
    std::span<const std::byte> packet)
{
    init_crypto();

    if(packet.size() < encrypted_header_size + encrypted_tag_size)
        return detail::make_unexpected(encrypt_error::invalid_header);

    auto hdr = deserialize_header(packet.data());

    if(hdr.magic != encrypted_magic)
        return detail::make_unexpected(encrypt_error::invalid_header);

    if(hdr.version != encrypted_version)
        return detail::make_unexpected(encrypt_error::unsupported_version);

    // The AAD must match the serialized header used during encrypt.
    const auto header_bytes = serialize_header(hdr);

    if((hdr.flags & flag_encrypted) != 0)
        return decrypt_sealed(key, hdr, header_bytes, packet);
    return decrypt_authenticated(key, hdr, header_bytes, packet);
}

}
