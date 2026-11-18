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

using socket_type = mdnspp::encrypt::encrypted_socket<mdnspp::fuzz::fuzz_socket>;
using mutation_list = std::array<std::pair<uint16_t, uint8_t>, 3>;

mdnspp::encrypt::encrypt_socket_options send_options(mdnspp::fuzz::input_reader &in, uint8_t cfg)
{
    mdnspp::encrypt::encrypt_socket_options opts;
    opts.encrypt.psk = mdnspp::encrypt::secure_key{fixed_key()};
    opts.encrypt.sender_id = in.u32() | 1u;
    opts.encrypt.initial_epoch = in.u8() % 4;
    opts.encrypt.auth_only = (cfg & 0x20) != 0;
    return opts;
}

mdnspp::encrypt::encrypt_socket_options recv_options(mdnspp::fuzz::input_reader &in, uint8_t cfg)
{
    auto key = fixed_key();
    if((cfg & 0x40) != 0)
        key[0] ^= std::byte{0x01};

    mdnspp::encrypt::encrypt_socket_options opts;
    opts.encrypt.psk = mdnspp::encrypt::secure_key{key};
    opts.encrypt.sender_id = 0xFFFFFFFFu;
    opts.encrypt.initial_epoch = in.u8() % 4;
    opts.encrypt.accept_cleartext = (cfg & 0x10) != 0;
    opts.encrypt.detection = static_cast<mdnspp::encrypt::cleartext_detection>(cfg % 3);
    opts.encrypt.recv_mode = static_cast<mdnspp::encrypt::receive_mode>((cfg >> 2) % 3);
    opts.encrypt.replay_window_size = static_cast<uint16_t>(in.u16() % 256);
    opts.encrypt.max_senders = 4;
    opts.encrypt.max_sessions_per_sender = 2;
    return opts;
}

// Rotating the receiver zero to two times makes the epoch/grace logic and the
// previous-key path reachable.
void rotate_receiver(socket_type &receiver, uint8_t rotations)
{
    for(uint8_t i = 0; i < rotations; ++i)
    {
        auto rotated = fixed_key();
        rotated[1] = static_cast<std::byte>(i + 1);
        receiver.update_key(mdnspp::encrypt::secure_key{rotated},
                            mdnspp::encrypt::grace_period{.duration = std::chrono::seconds{60},
                                                          .packet_count = std::nullopt});
    }
}

mutation_list read_mutations(mdnspp::fuzz::input_reader &in, uint8_t count)
{
    mutation_list mutations{};
    for(uint8_t i = 0; i < count; ++i)
        mutations[i] = {in.u16(), in.u8()};
    return mutations;
}

void mutate(std::vector<std::byte> &packet, const mutation_list &mutations, uint8_t count)
{
    for(uint8_t i = 0; i < count && !packet.empty(); ++i)
    {
        auto [offset, value] = mutations[i];
        packet[offset % packet.size()] ^= static_cast<std::byte>(value);
    }
}

void deliver(socket_type &receiver, std::vector<std::byte> packet)
{
    receiver.inner().enqueue(std::move(packet));
    receiver.async_receive(
        [](std::error_code, const mdnspp::recv_metadata &, std::span<std::byte> out)
        {
            if(!out.empty())
            {
                volatile std::byte sink = out[0];
                (void)sink;
            }
        });
}

std::vector<std::byte> sealed_packet(socket_type &sender, const std::vector<std::byte> &payload)
{
    sender.send(mdnspp::endpoint{}, std::span<const std::byte>(payload));
    if(sender.inner().sent().empty())
        return {};
    return sender.inner().sent().front();
}

void fuzz_round_trip(mdnspp::fuzz::input_reader &in)
{
    mdnspp::fuzz::fuzz_executor ex;
    const uint8_t cfg = in.u8();
    auto send_opts = send_options(in, cfg);
    auto recv_opts = recv_options(in, cfg);

    std::error_code send_ec;
    std::error_code recv_ec;
    socket_type sender(ex, send_opts, send_ec);
    socket_type receiver(ex, recv_opts, recv_ec);
    if(send_ec || recv_ec)
        return;

    rotate_receiver(receiver, in.u8() % 3);
    const uint8_t mutate_count = in.u8() % 4;
    const auto mutations = read_mutations(in, mutate_count);
    auto packet = sealed_packet(sender, in.remaining_bytes(512));
    if(packet.empty())
        return;
    mutate(packet, mutations, mutate_count);
    deliver(receiver, packet);
    if((cfg & 0x80) != 0)
        deliver(receiver, packet);
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
