#ifndef HPP_GUARD_MDNSPP_BASIC_NIC_MONITOR_H
#define HPP_GUARD_MDNSPP_BASIC_NIC_MONITOR_H

#include "mdnspp/policy.h"
#include "mdnspp/network_interface.h"
#include "mdnspp/nic_group_options.h"

#include "mdnspp/detail/compat.h"
#include "mdnspp/detail/nic_diff.h"
#include "mdnspp/detail/locked_snapshot.h"

// The Linux netlink members need detail::native_socket_t and detail::invalid_socket.
#ifdef __linux__
#include "mdnspp/default/default_context.h"
#endif

#include <atomic>
#include <memory>
#include <vector>
#include <system_error>

namespace mdnspp {

template <policy_like P>
class basic_nic_monitor
{
#ifdef _WIN32
    struct thunk;
#endif

public:
    using executor_type = typename P::executor_type;
    using timer_type    = typename P::timer_type;

    basic_nic_monitor(const basic_nic_monitor &) = delete;
    basic_nic_monitor &operator=(const basic_nic_monitor &) = delete;
    basic_nic_monitor(basic_nic_monitor &&) = delete;
    basic_nic_monitor &operator=(basic_nic_monitor &&) = delete;

    explicit basic_nic_monitor(executor_type ex, nic_monitor_options opts = {})
        : m_executor(ex)
        , m_timer(ex)
        , m_opts(std::move(opts))
    {
        std::error_code ec;
        auto initial = enumerate(ec);
        if(!ec)
            m_snapshot.publish(std::move(initial));
    }

    ~basic_nic_monitor()
    {
        stop();
    }

    void on_added(move_only_function<void(const network_interface &)> cb)
    {
        auto weak = std::weak_ptr<bool>(m_alive);
        P::post(m_executor, [this, weak, cb = std::move(cb)]() mutable
        {
            if(weak.expired()) return;
            m_on_added = std::move(cb);
        });
    }

    void on_removed(move_only_function<void(const network_interface &)> cb)
    {
        auto weak = std::weak_ptr<bool>(m_alive);
        P::post(m_executor, [this, weak, cb = std::move(cb)]() mutable
        {
            if(weak.expired()) return;
            m_on_removed = std::move(cb);
        });
    }

    void start()
    {
        m_stopped.store(false, std::memory_order_release);

        if(m_opts.enumerator || !start_native_backend())
            schedule_poll();
    }

    void stop()
    {
        if(m_stopped.exchange(true, std::memory_order_acq_rel))
            return;

        m_timer.cancel();
        stop_native_backend();

        // Expires the weak_ptrs held by callbacks already posted.
        m_alive.reset();
        m_alive = std::make_shared<bool>(true);
    }

    std::vector<network_interface> current() const
    {
        return m_snapshot.copy();
    }

private:
    std::shared_ptr<bool> m_alive{std::make_shared<bool>(true)};
    executor_type m_executor;
    timer_type m_timer;
    std::atomic<bool> m_stopped{true};
    nic_monitor_options m_opts;

    move_only_function<void(const network_interface &)> m_on_added;
    move_only_function<void(const network_interface &)> m_on_removed;

    detail::locked_snapshot<network_interface> m_snapshot;

#ifdef __linux__
    detail::native_socket_t m_nl_fd{detail::invalid_socket};
    timer_type m_nl_timer{m_executor};
#endif
#ifdef __APPLE__
    void *m_path_monitor{nullptr}; // nw_path_monitor_t, opaque until the backend unit
#endif
#ifdef _WIN32
    void *m_change_handle{nullptr}; // HANDLE, opaque until the backend unit
    std::weak_ptr<bool> m_weak_for_callback;
#endif

    void apply_diff(std::vector<network_interface> new_list)
    {
        auto weak = std::weak_ptr<bool>(m_alive);
        if(auto previous = m_snapshot.get())
        {
            for(auto &change : detail::diff_nics(*previous, new_list))
                post_change(std::move(change), weak);
        }
        m_snapshot.publish(std::move(new_list));
    }

    void post_change(detail::nic_change change, const std::weak_ptr<bool> &weak)
    {
        if(!callback_for(change.kind))
            return;
        P::post(m_executor, [this, weak, change = std::move(change)]
        {
            if(weak.expired()) return;
            callback_for(change.kind)(change.iface);
        });
    }

    move_only_function<void(const network_interface &)> &callback_for(detail::nic_change_kind kind)
    {
        return kind == detail::nic_change_kind::removed ? m_on_removed : m_on_added;
    }

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
            auto interfaces = enumerate(enum_ec);
            if(!enum_ec)
                apply_diff(std::move(interfaces));
            schedule_poll();
        });
    }

    std::vector<network_interface> enumerate(std::error_code &ec)
    {
        if(m_opts.enumerator)
            return m_opts.enumerator(ec);
        return enumerate_interfaces(ec);
    }

    bool start_native_backend();

    void stop_native_backend();

#ifdef __linux__
    void arm_netlink_poll();
#endif
};

}

#include "mdnspp/detail/nic_monitor_backends.h"

#endif
