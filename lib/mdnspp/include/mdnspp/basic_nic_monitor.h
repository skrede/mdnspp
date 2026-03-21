#ifndef HPP_GUARD_MDNSPP_BASIC_NIC_MONITOR_H
#define HPP_GUARD_MDNSPP_BASIC_NIC_MONITOR_H

#include "mdnspp/policy.h"
#include "mdnspp/nic_group_options.h"
#include "mdnspp/network_interface.h"

#include "mdnspp/detail/compat.h"

// Native socket types are required for the Linux AF_NETLINK member declarations.
// default_context.h defines detail::native_socket_t and detail::invalid_socket.
#ifdef __linux__
#include "mdnspp/default/default_context.h"
#endif

#include <mutex>
#include <atomic>
#include <memory>
#include <vector>
#include <algorithm>
#include <system_error>

namespace mdnspp {

// basic_nic_monitor<P> — Policy-templated NIC change detector.
//
// Detects network interface additions and removals via platform-native APIs
// where available (Linux: AF_NETLINK, macOS: nw_path_monitor,
// Windows: NotifyIpInterfaceChange). Falls back to timer-based polling on
// unsupported platforms.
//
// Lifecycle:
//   1. Construct with (ex, opts)
//   2. on_added(cb) / on_removed(cb) — register change callbacks
//   3. start() — begin monitoring
//   4. stop()  — idempotent; cancels all timers and native handles
//
// Thread safety:
//   on_added(), on_removed(), current(), start(), stop() may be called from
//   any thread. Callbacks are delivered on the Policy executor via P::post().

template <Policy P>
class basic_nic_monitor
{
public:
    using executor_type = typename P::executor_type;
    using timer_type    = typename P::timer_type;

    basic_nic_monitor(const basic_nic_monitor &) = delete;
    basic_nic_monitor &operator=(const basic_nic_monitor &) = delete;
    basic_nic_monitor(basic_nic_monitor &&) = delete;
    basic_nic_monitor &operator=(basic_nic_monitor &&) = delete;

    /// Construct and take an initial interface snapshot.
    /// @param ex    Executor to deliver callbacks on.
    /// @param opts  Monitoring options (poll interval for fallback).
    explicit basic_nic_monitor(executor_type ex, nic_monitor_options opts = {})
        : m_executor(ex)
        , m_timer(ex)
        , m_opts(std::move(opts))
    {
        std::error_code ec;
        auto initial = enumerate_interfaces(ec);
        if(!ec)
        {
            std::lock_guard lock(m_snapshot_mutex);
            m_snapshot = std::make_shared<const std::vector<network_interface>>(
                std::move(initial));
        }
    }

    ~basic_nic_monitor()
    {
        stop();
    }

    /// Register a callback fired (on the executor) when a NIC is added or changes.
    void on_added(detail::move_only_function<void(const network_interface &)> cb)
    {
        m_on_added = std::move(cb);
    }

    /// Register a callback fired (on the executor) when a NIC is removed or changes.
    void on_removed(detail::move_only_function<void(const network_interface &)> cb)
    {
        m_on_removed = std::move(cb);
    }

    /// Begin monitoring. Tries platform-native backend; falls back to polling.
    void start()
    {
        m_stopped.store(false, std::memory_order_release);

        if(!start_native_backend())
            schedule_poll();
    }

    /// Stop monitoring. Idempotent.
    void stop()
    {
        if(m_stopped.exchange(true, std::memory_order_acq_rel))
            return;

        m_timer.cancel();
        stop_native_backend();

        // Reset alive sentinel — invalidates any pending posted callbacks.
        m_alive.reset();
        m_alive = std::make_shared<bool>(true);
    }

    /// Return a snapshot of the current interface list.
    /// Thread-safe: lock is held only long enough to copy the shared_ptr.
    std::vector<network_interface> current() const
    {
        std::shared_ptr<const std::vector<network_interface>> snap;
        {
            std::lock_guard lock(m_snapshot_mutex);
            snap = m_snapshot;
        }
        return snap ? *snap : std::vector<network_interface>{};
    }

private:
    // -------------------------------------------------------------------------
    // Diff and callback delivery
    // -------------------------------------------------------------------------

    /// Compare old snapshot against new_list. Fire m_on_removed then m_on_added
    /// for each change. For a changed interface (same index, different state),
    /// fire remove+add in sequence (treat as remove/re-add).
    void apply_diff(std::vector<network_interface> new_list)
    {
        std::shared_ptr<const std::vector<network_interface>> old_snap;
        {
            std::lock_guard lock(m_snapshot_mutex);
            old_snap = m_snapshot;
        }

        const auto *old_ptr = old_snap ? old_snap.get() : nullptr;

        // Build sorted views by index for O(n log n) diff.
        auto index_of = [](const network_interface &iface) noexcept
        {
            return iface.index;
        };

        auto find_by_index = [](const std::vector<network_interface> &vec,
                                unsigned int idx) -> const network_interface *
        {
            auto it = std::find_if(vec.begin(), vec.end(),
                [idx](const network_interface &i) { return i.index == idx; });
            return it != vec.end() ? &*it : nullptr;
        };

        auto weak = std::weak_ptr<bool>(m_alive);

        if(old_ptr)
        {
            // Detect removals and changes
            for(const auto &old_iface : *old_ptr)
            {
                const auto *new_iface = find_by_index(new_list, old_iface.index);
                if(!new_iface)
                {
                    // Removed
                    if(m_on_removed)
                    {
                        P::post(m_executor, [this, weak, iface = old_iface]
                        {
                            if(weak.expired()) return;
                            m_on_removed(iface);
                        });
                    }
                }
                else if(new_iface->is_up != old_iface.is_up ||
                        new_iface->ipv4_address != old_iface.ipv4_address ||
                        new_iface->ipv6_address != old_iface.ipv6_address)
                {
                    // Changed: remove then add
                    if(m_on_removed)
                    {
                        P::post(m_executor, [this, weak, iface = old_iface]
                        {
                            if(weak.expired()) return;
                            m_on_removed(iface);
                        });
                    }
                    if(m_on_added)
                    {
                        P::post(m_executor, [this, weak, iface = *new_iface]
                        {
                            if(weak.expired()) return;
                            m_on_added(iface);
                        });
                    }
                }
            }

            // Detect additions
            for(const auto &new_iface : new_list)
            {
                if(!find_by_index(*old_ptr, new_iface.index))
                {
                    if(m_on_added)
                    {
                        P::post(m_executor, [this, weak, iface = new_iface]
                        {
                            if(weak.expired()) return;
                            m_on_added(iface);
                        });
                    }
                }
            }
        }

        // Update COW snapshot
        {
            std::lock_guard lock(m_snapshot_mutex);
            m_snapshot = std::make_shared<const std::vector<network_interface>>(
                std::move(new_list));
        }

        (void)index_of; // suppress unused-lambda warning
    }

    // -------------------------------------------------------------------------
    // Polling fallback
    // -------------------------------------------------------------------------

    void schedule_poll()
    {
        if(m_stopped.load(std::memory_order_acquire))
            return;

        m_timer.expires_after(m_opts.poll_interval);
        auto weak = std::weak_ptr<bool>(m_alive);
        m_timer.async_wait([this, weak](std::error_code ec)
        {
            if(ec || weak.expired()) return;
            std::error_code enum_ec;
            auto interfaces = enumerate_interfaces(enum_ec);
            if(!enum_ec)
                apply_diff(std::move(interfaces));
            schedule_poll();
        });
    }

    // -------------------------------------------------------------------------
    // Platform backend — implemented in detail/nic_monitor_backends.h
    // -------------------------------------------------------------------------

    /// Attempt to start the platform-native backend.
    /// Returns true on success (polling fallback not needed),
    /// false to fall through to the polling fallback.
    bool start_native_backend();

    /// Release platform-native resources acquired by start_native_backend().
    void stop_native_backend();

    // -------------------------------------------------------------------------
    // Data members
    // -------------------------------------------------------------------------

    std::shared_ptr<bool> m_alive{std::make_shared<bool>(true)};
    executor_type m_executor;
    timer_type m_timer;
    std::atomic<bool> m_stopped{true};
    nic_monitor_options m_opts;

    detail::move_only_function<void(const network_interface &)> m_on_added;
    detail::move_only_function<void(const network_interface &)> m_on_removed;

    mutable std::mutex m_snapshot_mutex;
    std::shared_ptr<const std::vector<network_interface>> m_snapshot;

    // Platform-specific backend state — defined under #ifdef in backends header.
#ifdef __linux__
    detail::native_socket_t m_nl_fd{detail::invalid_socket};
    timer_type m_nl_timer{m_executor};
#endif
#ifdef __APPLE__
    void *m_path_monitor{nullptr}; // nw_path_monitor_t — opaque until backends header
#endif
#ifdef _WIN32
    void *m_change_handle{nullptr}; // HANDLE — opaque until backends header
    std::weak_ptr<bool> m_weak_for_callback;
#endif
};

}

// Platform-specific backend implementations
#include "mdnspp/detail/nic_monitor_backends.h"

#endif
