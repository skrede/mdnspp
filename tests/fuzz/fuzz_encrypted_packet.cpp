#include "mdnspp/encrypt/aead.h"
#include "mdnspp/encrypt/encrypted_socket.h"
#include "mdnspp/encrypt/encrypt_socket_options.h"

#include <span>
#include <array>
#include <queue>
#include <chrono>
#include <vector>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <utility>
#include <optional>
#include <system_error>

// Two modes, selected by the first input byte:
// - raw decrypt: the remaining input is fed directly to aead_decrypt with a
//   fixed key (header parsing and tag verification).
// - round-trip: input-derived options configure a sender and a receiver
//   encrypted_socket; an input-derived payload is encrypted with the real key,
//   selected bytes are mutated, and the result is pushed through the full
//   receive path twice (detection modes, receive_mode filtering, epoch
//   selection, replay window), so the logic past tag verification is reached.

namespace {

struct fuzz_executor
{
};

// Minimal socket_like implementation that records sends and replays an
// enqueued packet on async_receive.
class fuzz_socket
{
public:
    explicit fuzz_socket(fuzz_executor &)
    {
    }

    explicit fuzz_socket(fuzz_executor &, std::error_code &)
    {
    }

    explicit fuzz_socket(fuzz_executor &, const mdnspp::socket_options &)
    {
    }

    explicit fuzz_socket(fuzz_executor &, const mdnspp::socket_options &, std::error_code &)
    {
    }

    void send(const mdnspp::endpoint &, std::span<const std::byte> data)
    {
        m_sent.emplace_back(data.begin(), data.end());
    }

    void send(const mdnspp::endpoint &, std::span<const std::byte> data, std::error_code &)
    {
        m_sent.emplace_back(data.begin(), data.end());
    }

    void async_receive(
        mdnspp::move_only_function<void(std::error_code, const mdnspp::recv_metadata &, std::span<std::byte>)> handler)
    {
        if(m_queue.empty())
            return;
        auto packet = std::move(m_queue.front());
        m_queue.pop();
        handler(std::error_code{}, mdnspp::recv_metadata{}, std::span<std::byte>(packet));
    }

    void close()
    {
    }

    void enqueue(std::vector<std::byte> packet)
    {
        m_queue.push(std::move(packet));
    }

    std::vector<std::vector<std::byte>> &sent() noexcept
    {
        return m_sent;
    }

private:
    std::vector<std::vector<std::byte>> m_sent;
    std::queue<std::vector<std::byte>> m_queue;
};

static_assert(mdnspp::socket_like<fuzz_socket>, "fuzz_socket must satisfy socket_like");

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

std::array<std::byte, 32> fixed_key()
{
    std::array<std::byte, 32> key{};
    key.fill(std::byte{0x42});
    return key;
}

void fuzz_raw_decrypt(const uint8_t *data, size_t size)
{
    auto key = fixed_key();
    auto result = mdnspp::encrypt::aead_decrypt(
        std::span<const std::byte, 32>(key),
        std::span<const std::byte>(reinterpret_cast<const std::byte *>(data), size));
    if(result.has_value() && !result->empty())
    {
        volatile std::byte sink = (*result)[0];
        (void)sink;
    }
}

void fuzz_round_trip(input_reader &in)
{
    using socket_type = mdnspp::encrypt::encrypted_socket<fuzz_socket>;

    fuzz_executor ex;

    const uint8_t cfg = in.u8();
    const auto detection = static_cast<mdnspp::encrypt::cleartext_detection>(cfg % 3);
    const auto recv_mode = static_cast<mdnspp::encrypt::receive_mode>((cfg >> 2) % 3);
    const bool accept_cleartext = (cfg & 0x10) != 0;
    const bool auth_only = (cfg & 0x20) != 0;
    const bool wrong_key = (cfg & 0x40) != 0;
    const bool replay_same_packet = (cfg & 0x80) != 0;

    mdnspp::encrypt::encrypt_socket_options send_opts;
    send_opts.encrypt.psk = mdnspp::encrypt::secure_key{fixed_key()};
    send_opts.encrypt.sender_id = in.u32() | 1u;
    send_opts.encrypt.initial_epoch = in.u8() % 4;
    send_opts.encrypt.auth_only = auth_only;

    auto recv_key = fixed_key();
    if(wrong_key)
        recv_key[0] ^= std::byte{0x01};

    mdnspp::encrypt::encrypt_socket_options recv_opts;
    recv_opts.encrypt.psk = mdnspp::encrypt::secure_key{recv_key};
    recv_opts.encrypt.sender_id = 0xFFFFFFFFu;
    recv_opts.encrypt.initial_epoch = in.u8() % 4;
    recv_opts.encrypt.accept_cleartext = accept_cleartext;
    recv_opts.encrypt.detection = detection;
    recv_opts.encrypt.recv_mode = recv_mode;
    recv_opts.encrypt.replay_window_size = static_cast<uint16_t>(in.u16() % 256);
    recv_opts.encrypt.max_senders = 4;

    std::error_code send_ec;
    std::error_code recv_ec;
    socket_type sender(ex, send_opts, send_ec);
    socket_type receiver(ex, recv_opts, recv_ec);
    if(send_ec || recv_ec)
        return;

    // Rotate the receiver zero to two times so the epoch/grace logic and the
    // previous-key path are reachable.
    const uint8_t rotations = in.u8() % 3;
    for(uint8_t i = 0; i < rotations; ++i)
    {
        auto rotated = fixed_key();
        rotated[1] = static_cast<std::byte>(i + 1);
        receiver.update_key(mdnspp::encrypt::secure_key{rotated},
                            mdnspp::encrypt::grace_period{.duration = std::chrono::seconds{60},
                                                          .packet_count = std::nullopt});
    }

    const uint8_t mutate_count = in.u8() % 4;
    std::array<std::pair<uint16_t, uint8_t>, 3> mutations{};
    for(uint8_t i = 0; i < mutate_count; ++i)
        mutations[i] = {in.u16(), in.u8()};

    auto payload = in.remaining_bytes(512);

    sender.send(mdnspp::endpoint{}, std::span<const std::byte>(payload));
    if(sender.inner().sent().empty())
        return;
    auto packet = sender.inner().sent().front();

    for(uint8_t i = 0; i < mutate_count; ++i)
    {
        if(packet.empty())
            break;
        auto [offset, value] = mutations[i];
        packet[offset % packet.size()] ^= static_cast<std::byte>(value);
    }

    auto deliver = [&receiver](std::vector<std::byte> pkt)
    {
        receiver.inner().enqueue(std::move(pkt));
        receiver.async_receive(
            [](std::error_code, const mdnspp::recv_metadata &, std::span<std::byte> out)
            {
                if(!out.empty())
                {
                    volatile std::byte sink = out[0];
                    (void)sink;
                }
            });
    };

    deliver(packet);
    if(replay_same_packet)
        deliver(packet);
}

}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    static const bool crypto_ok = mdnspp::encrypt::init_crypto();
    if(!crypto_ok || size == 0)
        return 0;

    input_reader in(data, size);
    const uint8_t mode = in.u8();

    if(mode % 2 == 0)
        fuzz_raw_decrypt(data + 1, size - 1);
    else
        fuzz_round_trip(in);

    return 0;
}
