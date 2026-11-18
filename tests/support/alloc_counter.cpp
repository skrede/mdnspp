#include "support/alloc_counter.h"

#include <new>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstdlib>

// Replaces the global allocation functions ([new.delete]); linked only into targets that count allocations.
namespace {

std::atomic<uint64_t> allocations{0};

void *take(std::size_t size) noexcept
{
    allocations.fetch_add(1, std::memory_order_relaxed);
    return std::malloc(size == 0 ? 1 : size);
}

void *take_aligned(std::size_t size, std::align_val_t align) noexcept
{
    allocations.fetch_add(1, std::memory_order_relaxed);
    const std::size_t bytes = size == 0 ? 1 : size;
#if defined(_MSC_VER)
    return _aligned_malloc(bytes, static_cast<std::size_t>(align));
#else
    void *block = nullptr;
    const std::size_t alignment = static_cast<std::size_t>(align) < sizeof(void *)
                                      ? sizeof(void *)
                                      : static_cast<std::size_t>(align);
    return posix_memalign(&block, alignment, bytes) == 0 ? block : nullptr;
#endif
}

void *or_throw(void *block)
{
    if(block == nullptr)
        throw std::bad_alloc();
    return block;
}

void give_back(void *block) noexcept
{
    std::free(block);
}

void give_back_aligned(void *block) noexcept
{
#if defined(_MSC_VER)
    _aligned_free(block);
#else
    std::free(block);
#endif
}

}

namespace mdnspp::test_support {

uint64_t allocation_count() noexcept
{
    return allocations.load(std::memory_order_relaxed);
}

void reset_allocation_count() noexcept
{
    allocations.store(0, std::memory_order_relaxed);
}

}

void *operator new(std::size_t size) { return or_throw(take(size)); }

void *operator new[](std::size_t size) { return or_throw(take(size)); }

void *operator new(std::size_t size, const std::nothrow_t &) noexcept { return take(size); }

void *operator new[](std::size_t size, const std::nothrow_t &) noexcept { return take(size); }

void *operator new(std::size_t size, std::align_val_t align) { return or_throw(take_aligned(size, align)); }

void *operator new[](std::size_t size, std::align_val_t align) { return or_throw(take_aligned(size, align)); }

void *operator new(std::size_t size, std::align_val_t align, const std::nothrow_t &) noexcept
{
    return take_aligned(size, align);
}

void *operator new[](std::size_t size, std::align_val_t align, const std::nothrow_t &) noexcept
{
    return take_aligned(size, align);
}

void operator delete(void *block) noexcept { give_back(block); }

void operator delete[](void *block) noexcept { give_back(block); }

void operator delete(void *block, std::size_t) noexcept { give_back(block); }

void operator delete[](void *block, std::size_t) noexcept { give_back(block); }

void operator delete(void *block, const std::nothrow_t &) noexcept { give_back(block); }

void operator delete[](void *block, const std::nothrow_t &) noexcept { give_back(block); }

void operator delete(void *block, std::align_val_t) noexcept { give_back_aligned(block); }

void operator delete[](void *block, std::align_val_t) noexcept { give_back_aligned(block); }

void operator delete(void *block, std::size_t, std::align_val_t) noexcept { give_back_aligned(block); }

void operator delete[](void *block, std::size_t, std::align_val_t) noexcept { give_back_aligned(block); }

void operator delete(void *block, std::align_val_t, const std::nothrow_t &) noexcept { give_back_aligned(block); }

void operator delete[](void *block, std::align_val_t, const std::nothrow_t &) noexcept { give_back_aligned(block); }
