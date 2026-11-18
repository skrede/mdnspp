#include "fuzz_input.h"
#include "fuzz_socket.h"

#include "mdnspp/encrypt/aead.h"
#include "mdnspp/encrypt/encrypted_socket.h"
#include "mdnspp/encrypt/encrypt_socket_options.h"

#include <span>
#include <array>
#include <chrono>
#include <vector>
#include <cstddef>
#include <cstdint>
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

std::array<std::byte, 32> fixed_key()
{
    std::array<std::byte, 32> key{};
    key.fill(std::byte{0x42});
    return key;
}

void fuzz_raw_decrypt(const uint8_t *data, size_t size)
{
    auto key = fixed_key();
    std::vector<std::byte> out(size);
    std::size_t written = 0;
    auto ec = mdnspp::encrypt::aead_decrypt(
        std::span<const std::byte, 32>(key),
        std::span<const std::byte>(reinterpret_cast<const std::byte *>(data), size),
        out, written);
    if(!ec && written > 0)
    {
        volatile std::byte sink = out[0];
        (void)sink;
    }
}

void fuzz_round_trip(mdnspp::fuzz::input_reader &in)
{
    using socket_type = mdnspp::encrypt::encrypted_socket<mdnspp::fuzz::fuzz_socket>;

    mdnspp::fuzz::fuzz_executor ex;

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
    recv_opts.encrypt.max_sessions_per_sender = 2;

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

    mdnspp::fuzz::input_reader in(data, size);
    const uint8_t mode = in.u8();

    if(mode % 2 == 0)
        fuzz_raw_decrypt(data + 1, size - 1);
    else
        fuzz_round_trip(in);

    return 0;
}
