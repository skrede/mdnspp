#include <mdnspp/encrypt/aead.h>
#include <mdnspp/encrypt/defaults.h>

#include <array>
#include <mutex>
#include <chrono>
#include <thread>
#include <cstddef>
#include <cstdint>
#include <utility>
#include <iostream>
#include <system_error>
#include <condition_variable>

// Demonstrate encrypted mDNS key rotation.
//
// Key rotation replaces the active PSK on a live encrypted_socket. Rotation
// needs coordinated timing: a peer that has rotated accepts old-epoch traffic
// from peers that have not rotated yet, but only for its grace period, and a
// peer that has not rotated does not hold the new key and drops new-epoch
// traffic until its own update_key() call.
//
// Epoch semantics:
//   Each encrypted_socket tracks a 32-bit epoch counter, starting at
//   encrypt_options::initial_epoch (default 0). update_key() increments the
//   epoch and stores the new key. Every outgoing packet carries the current
//   epoch in the wire header.
//
// Thread safety:
//   update_key() may be called from any thread, concurrently with the receive
//   path; the socket's key, epoch, and grace-period state are guarded by an
//   internal mutex.
//
// Dual-key overlap:
//   Immediately after update_key(), the socket holds two keys:
//     - current key (epoch N):   used to encrypt outgoing packets and to
//       decrypt incoming packets with epoch = N or N+1, and N-1 once no
//       previous key is held (this covers peers whose epoch counter runs one
//       ahead or behind with the same key).
//     - previous key (epoch N-1): used to decrypt incoming packets with
//       epoch = N-1, until the grace period expires.
//   Packets with any other epoch are rejected immediately.
//
// Grace period:
//   grace_period carries the overlap window. If neither duration nor
//   packet_count is set, update_key() applies a default duration bound of
//   30 seconds (encrypted_socket::default_grace_duration). When both are set,
//   the grace period ends when either condition is first satisfied.
//     .duration     -- expire after this wall-clock duration
//     .packet_count -- expire after this many old-epoch packets have been
//                      accepted (authenticated with the previous key and not
//                      rejected as replays)
//
// Lazy expiry:
//   The grace period is checked inline on each sent and received packet.
//   There is no background timer. The previous key is zeroized at the first
//   send or receive after the grace period expires.
//
// Peer coordination:
//   All peers must call update_key() with the same new key within the grace
//   window of the earliest rotator. There is no staged next-key API and no
//   negotiation: distribute the new key out of band and schedule a rotation
//   time that all peers act on within a nominated window, shorter than the
//   grace period.
//
// After grace expires:
//   Packets from the previous epoch fail authentication under the new key and
//   are rejected. Any peer that has not rotated will be unable to communicate
//   until it also calls update_key() with the new key. A peer that restarts
//   after the rotation must be provisioned with the new key and
//   encrypt_options::initial_epoch set to the group's current epoch.

static std::array<std::byte, 32> sequential_key(uint8_t first)
{
    std::array<std::byte, 32> key{};
    for(std::size_t i = 0; i < key.size(); ++i)
        key[i] = std::byte(first + i);
    return key;
}

static mdnspp::encrypt::encrypt_socket_options make_socket_options()
{
    std::array<std::byte, 32> key = sequential_key(0x01);
    mdnspp::encrypt::encrypt_socket_options sock_opts{
        .encrypt = {
            .psk       = mdnspp::encrypt::secure_key{key},
            .sender_id = 0x00000001,
        },
    };
    // secure_key copies the key material; wipe the stack source buffer.
    mdnspp::encrypt::secure_zero(key.data(), key.size());
    return sock_opts;
}

static mdnspp::observer_options make_observer_options()
{
    return mdnspp::observer_options{
        .on_record = [](const mdnspp::endpoint &sender,
                        const mdnspp::mdns_record_variant &rec)
        {
            std::visit([&sender](const auto &r) {
                std::cout << sender << " -> " << r << std::endl;
            }, rec);
        }
    };
}

static void rotate_key(mdnspp::encrypt::encrypted_observer &obs)
{
    std::array<std::byte, 32> new_raw_key = sequential_key(0xA1);

    // update_key() is called on the encrypted_socket, accessible via socket().
    // socket() returns the encrypted_socket<InnerSocket> for encrypted_policy.
    // Calling it from this thread while the executor thread decrypts is
    // permitted: key state is guarded by an internal mutex.
    // The grace period of 30 seconds keeps accepting old-epoch packets from
    // peers that have not yet rotated during the transition window.
    obs.socket().update_key(
        mdnspp::encrypt::secure_key{new_raw_key},
        mdnspp::encrypt::grace_period{
            .duration     = std::chrono::seconds{30},
            .packet_count = 1000,
        }
    );
    // secure_key copies the key material; wipe the stack source buffer.
    mdnspp::encrypt::secure_zero(new_raw_key.data(), new_raw_key.size());

    std::cout << "key rotated -- epoch incremented, grace period: 30 s or 1000 packets" << std::endl;
}

class stop_signal
{
public:
    stop_signal()
        : m_stopped(false)
    {
    }

    void request()
    {
        std::lock_guard lock(m_mutex);
        m_stopped = true;
        m_wake.notify_all();
    }

    // Returns false when a stop is requested before the delay has elapsed.
    bool sleep_for(std::chrono::seconds delay)
    {
        std::unique_lock lock(m_mutex);
        return !m_wake.wait_for(lock, delay, [this] { return m_stopped; });
    }

private:
    std::mutex m_mutex;
    std::condition_variable m_wake;
    bool m_stopped;
};

// Simulate a key rotation after 5 seconds.
// In a real application, the rotation would be triggered by an application-
// level signal (e.g., a scheduled rotation, an admin command, or a shared
// rotation notification received over a side-channel).
static void rotate_then_stop(mdnspp::encrypt::encrypted_observer &obs, mdnspp::context &ctx, stop_signal &stop)
{
    if(!stop.sleep_for(std::chrono::seconds{5}))
        return;
    rotate_key(obs);

    // After 35 seconds the grace period has expired on this peer. Any packets
    // still arriving with the old epoch are rejected from this point on.
    if(stop.sleep_for(std::chrono::seconds{35}))
        ctx.stop();
}

int main()
{
    mdnspp::encrypt::encrypt_socket_options sock_opts = make_socket_options();

    mdnspp::context ctx;
    mdnspp::encrypt::encrypted_observer obs{ctx, make_observer_options(), std::move(sock_opts)};

    obs.async_observe([&ctx](std::error_code ec)
    {
        if (ec)
            std::cerr << "observe error: " << ec.message() << std::endl;
        ctx.stop();
    });

    stop_signal stop;
    std::thread rotation_thread{[&obs, &ctx, &stop] { rotate_then_stop(obs, ctx, stop); }};

    std::error_code ec;
    ctx.run(ec);
    stop.request();
    rotation_thread.join();
    if(ec)
        std::cerr << "run error: " << ec.message() << std::endl;
    return ec ? 1 : 0;
}
