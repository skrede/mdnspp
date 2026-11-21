#ifndef HPP_GUARD_MDNSPP_DETAIL_LOCKED_SNAPSHOT_H
#define HPP_GUARD_MDNSPP_DETAIL_LOCKED_SNAPSHOT_H

#include <mutex>
#include <memory>
#include <vector>
#include <utility>

namespace mdnspp::detail {

template <typename T>
class locked_snapshot
{
public:
    using pointer = std::shared_ptr<const std::vector<T>>;

    locked_snapshot()
        : m_snapshot()
        , m_mutex()
    {
    }

    void publish(std::vector<T> items)
    {
        std::lock_guard lock(m_mutex);
        m_snapshot = std::make_shared<const std::vector<T>>(std::move(items));
    }

    pointer get() const
    {
        std::lock_guard lock(m_mutex);
        return m_snapshot;
    }

    std::vector<T> copy() const
    {
        pointer snap = get();
        return snap ? *snap : std::vector<T>{};
    }

private:
    pointer m_snapshot;
    mutable std::mutex m_mutex;
};

}

#endif
