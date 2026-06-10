#include "mdnspp/encrypt/aead.h"
#include "mdnspp/encrypt/secure_key.h"
#include "mdnspp/encrypt/packet_header.h"

#include <sodium.h>

#include <mutex>
#include <cstdint>

namespace {

// Big-endian write helpers

void write_be16(std::byte *p, uint16_t v)
{
    p[0] = static_cast<std::byte>(static_cast<uint8_t>((v >> 8) & 0xFF));
    p[1] = static_cast<std::byte>(static_cast<uint8_t>(v & 0xFF));
}

void write_be32(std::byte *p, uint32_t v)
{
    p[0] = static_cast<std::byte>(static_cast<uint8_t>((v >> 24) & 0xFF));
    p[1] = static_cast<std::byte>(static_cast<uint8_t>((v >> 16) & 0xFF));
    p[2] = static_cast<std::byte>(static_cast<uint8_t>((v >> 8) & 0xFF));
    p[3] = static_cast<std::byte>(static_cast<uint8_t>(v & 0xFF));
}

void write_be64(std::byte *p, uint64_t v)
{
    p[0] = static_cast<std::byte>(static_cast<uint8_t>((v >> 56) & 0xFF));
    p[1] = static_cast<std::byte>(static_cast<uint8_t>((v >> 48) & 0xFF));
    p[2] = static_cast<std::byte>(static_cast<uint8_t>((v >> 40) & 0xFF));
    p[3] = static_cast<std::byte>(static_cast<uint8_t>((v >> 32) & 0xFF));
    p[4] = static_cast<std::byte>(static_cast<uint8_t>((v >> 24) & 0xFF));
    p[5] = static_cast<std::byte>(static_cast<uint8_t>((v >> 16) & 0xFF));
    p[6] = static_cast<std::byte>(static_cast<uint8_t>((v >> 8) & 0xFF));
    p[7] = static_cast<std::byte>(static_cast<uint8_t>(v & 0xFF));
}

uint16_t read_be16(const std::byte *p)
{
    return static_cast<uint16_t>(
        (static_cast<uint16_t>(static_cast<uint8_t>(p[0])) << 8) |
        static_cast<uint16_t>(static_cast<uint8_t>(p[1])));
}

uint32_t read_be32(const std::byte *p)
{
    return (static_cast<uint32_t>(static_cast<uint8_t>(p[0])) << 24) |
           (static_cast<uint32_t>(static_cast<uint8_t>(p[1])) << 16) |
           (static_cast<uint32_t>(static_cast<uint8_t>(p[2])) << 8) |
            static_cast<uint32_t>(static_cast<uint8_t>(p[3]));
}

uint64_t read_be64(const std::byte *p)
{
    return (static_cast<uint64_t>(static_cast<uint8_t>(p[0])) << 56) |
           (static_cast<uint64_t>(static_cast<uint8_t>(p[1])) << 48) |
           (static_cast<uint64_t>(static_cast<uint8_t>(p[2])) << 40) |
           (static_cast<uint64_t>(static_cast<uint8_t>(p[3])) << 32) |
           (static_cast<uint64_t>(static_cast<uint8_t>(p[4])) << 24) |
           (static_cast<uint64_t>(static_cast<uint8_t>(p[5])) << 16) |
           (static_cast<uint64_t>(static_cast<uint8_t>(p[6])) << 8) |
            static_cast<uint64_t>(static_cast<uint8_t>(p[7]));
}

}

namespace mdnspp::encrypt {

// --- secure_key implementation ---

secure_key::secure_key(std::array<std::byte, key_size> key) noexcept
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

// --- packet_header serialize/deserialize ---

std::array<std::byte, encrypted_header_size> serialize_header(const encrypted_packet_header &hdr)
{
    std::array<std::byte, encrypted_header_size> buf{};
    std::byte *p = buf.data();

    // magic (2), version (1), flags (1)
    write_be16(p, hdr.magic);       p += 2;
    *p++ = static_cast<std::byte>(hdr.version);
    *p++ = static_cast<std::byte>(hdr.flags);

    // sender_id (4)
    write_be32(p, hdr.sender_id);   p += 4;

    // sequence (8)
    write_be64(p, hdr.sequence);    p += 8;

    // epoch (4)
    write_be32(p, hdr.epoch);       p += 4;

    // nonce (24)
    std::copy(hdr.nonce.begin(), hdr.nonce.end(), p);

    return buf;
}

encrypted_packet_header deserialize_header(const std::byte *buf)
{
    encrypted_packet_header hdr;
    const std::byte *p = buf;

    hdr.magic     = read_be16(p);                                  p += 2;
    hdr.version   = static_cast<uint8_t>(*p++);
    hdr.flags     = static_cast<uint8_t>(*p++);
    hdr.sender_id = read_be32(p);                                  p += 4;
    hdr.sequence  = read_be64(p);                                  p += 8;
    hdr.epoch     = read_be32(p);                                  p += 4;

    std::copy(p, p + encrypted_nonce_size, hdr.nonce.begin());

    return hdr;
}

// --- secure_zero ---

void secure_zero(void *buf, std::size_t len) noexcept
{
    sodium_memzero(buf, len);
}

// --- init_crypto ---

bool init_crypto()
{
    static std::once_flag flag;
    static bool result = false;
    std::call_once(flag, []() {
        result = (sodium_init() != -1);
    });
    return result;
}

// --- aead_encrypt ---

std::vector<std::byte> aead_encrypt(
    std::span<const std::byte, 32> key,
    const encrypted_packet_header &hdr,
    std::span<const std::byte> plaintext)
{
    init_crypto();

    // Build header with a fresh random nonce
    encrypted_packet_header hdr_with_nonce = hdr;
    randombytes_buf(hdr_with_nonce.nonce.data(), encrypted_nonce_size);

    auto header_bytes = serialize_header(hdr_with_nonce);

    const bool encrypted_mode = (hdr_with_nonce.flags & flag_encrypted) != 0;

    if(encrypted_mode)
    {
        // Output: header + ciphertext + tag (standard AEAD mode)
        const std::size_t ciphertext_len = plaintext.size() + crypto_aead_xchacha20poly1305_ietf_ABYTES;
        std::vector<std::byte> output(encrypted_header_size + ciphertext_len);

        std::copy(header_bytes.begin(), header_bytes.end(), output.begin());

        unsigned long long actual_ciphertext_len = 0;
        crypto_aead_xchacha20poly1305_ietf_encrypt(
            reinterpret_cast<unsigned char *>(output.data() + encrypted_header_size),
            &actual_ciphertext_len,
            reinterpret_cast<const unsigned char *>(plaintext.data()),
            static_cast<unsigned long long>(plaintext.size()),
            reinterpret_cast<const unsigned char *>(header_bytes.data()),
            static_cast<unsigned long long>(encrypted_header_size),
            nullptr,  // nsec (unused by this construction)
            reinterpret_cast<const unsigned char *>(hdr_with_nonce.nonce.data()),
            reinterpret_cast<const unsigned char *>(key.data())
        );

        output.resize(encrypted_header_size + actual_ciphertext_len);
        return output;
    }
    else
    {
        // Auth-only mode: output is header + cleartext + 16-byte tag.
        // AAD = header bytes + plaintext (tag covers both).
        // An empty ciphertext message is passed to the detached variant so that
        // the auth tag is computed solely over the AAD (header + plaintext).
        std::vector<std::byte> output(encrypted_header_size + plaintext.size() + encrypted_tag_size);

        std::copy(header_bytes.begin(), header_bytes.end(), output.begin());
        std::copy(plaintext.begin(), plaintext.end(),
                  output.begin() + static_cast<std::ptrdiff_t>(encrypted_header_size));

        // Build the full AAD: header bytes followed by plaintext
        std::vector<unsigned char> aad;
        aad.resize(encrypted_header_size + plaintext.size());
        std::copy(header_bytes.begin(), header_bytes.end(),
                  reinterpret_cast<std::byte *>(aad.data()));
        std::copy(plaintext.begin(), plaintext.end(),
                  reinterpret_cast<std::byte *>(aad.data() + encrypted_header_size));

        unsigned char *tag_out = reinterpret_cast<unsigned char *>(
            output.data() + encrypted_header_size + plaintext.size());
        unsigned long long tag_len = 0;

        // Empty message — only the auth tag is computed from the AAD.
        // Provide a valid non-null pointer for ciphertext/message even though
        // their lengths are zero (satisfies libsodium nonnull attribute).
        unsigned char dummy = 0;
        crypto_aead_xchacha20poly1305_ietf_encrypt_detached(
            &dummy,     // ciphertext out (zero-length, pointer required non-null)
            tag_out,
            &tag_len,
            &dummy,     // message in (zero-length, pointer required non-null)
            0,
            aad.data(),
            static_cast<unsigned long long>(aad.size()),
            nullptr,    // nsec (unused)
            reinterpret_cast<const unsigned char *>(hdr_with_nonce.nonce.data()),
            reinterpret_cast<const unsigned char *>(key.data())
        );

        return output;
    }
}

// --- aead_decrypt ---

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

    // Serialize header for AAD (must match what was used during encrypt)
    auto header_bytes = serialize_header(hdr);

    const bool encrypted_mode = (hdr.flags & flag_encrypted) != 0;

    if(encrypted_mode)
    {
        const std::byte *ciphertext_ptr = packet.data() + encrypted_header_size;
        const std::size_t ciphertext_len = packet.size() - encrypted_header_size;

        std::vector<std::byte> plaintext(ciphertext_len - crypto_aead_xchacha20poly1305_ietf_ABYTES);
        unsigned long long plaintext_len = 0;

        int rc = crypto_aead_xchacha20poly1305_ietf_decrypt(
            reinterpret_cast<unsigned char *>(plaintext.data()),
            &plaintext_len,
            nullptr,  // nsec (unused)
            reinterpret_cast<const unsigned char *>(ciphertext_ptr),
            static_cast<unsigned long long>(ciphertext_len),
            reinterpret_cast<const unsigned char *>(header_bytes.data()),
            static_cast<unsigned long long>(encrypted_header_size),
            reinterpret_cast<const unsigned char *>(hdr.nonce.data()),
            reinterpret_cast<const unsigned char *>(key.data())
        );

        if(rc != 0)
            return detail::make_unexpected(encrypt_error::decrypt_failed);

        plaintext.resize(plaintext_len);
        return plaintext;
    }
    else
    {
        // Auth-only mode: packet is header + cleartext + 16-byte tag.
        const std::size_t payload_len = packet.size() - encrypted_header_size - encrypted_tag_size;

        const std::byte *payload_ptr = packet.data() + encrypted_header_size;
        const std::byte *tag_ptr = packet.data() + packet.size() - encrypted_tag_size;

        // Reconstruct the AAD used during encrypt: header bytes + cleartext payload
        std::vector<unsigned char> aad;
        aad.resize(encrypted_header_size + payload_len);
        std::copy(header_bytes.begin(), header_bytes.end(),
                  reinterpret_cast<std::byte *>(aad.data()));
        std::copy(payload_ptr, payload_ptr + payload_len,
                  reinterpret_cast<std::byte *>(aad.data() + encrypted_header_size));

        // Provide a valid non-null pointer for ciphertext even though its length
        // is zero (satisfies libsodium nonnull attribute on the output pointer).
        unsigned char dummy = 0;
        int rc = crypto_aead_xchacha20poly1305_ietf_decrypt_detached(
            &dummy,     // ciphertext out (zero-length, pointer required non-null)
            nullptr,    // nsec (unused)
            &dummy,     // ciphertext in (zero-length, pointer required non-null)
            0,
            reinterpret_cast<const unsigned char *>(tag_ptr),
            aad.data(),
            static_cast<unsigned long long>(aad.size()),
            reinterpret_cast<const unsigned char *>(hdr.nonce.data()),
            reinterpret_cast<const unsigned char *>(key.data())
        );

        if(rc != 0)
            return detail::make_unexpected(encrypt_error::decrypt_failed);

        std::vector<std::byte> plaintext(payload_len);
        std::copy(payload_ptr, payload_ptr + payload_len, plaintext.begin());
        return plaintext;
    }
}

}
