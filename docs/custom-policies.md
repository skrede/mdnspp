# Custom Policies

Every `basic_*` class template in mdnspp is parameterized on a `Policy`. A
Policy is a struct (or class) that provides an executor type, a socket type, and
a timer type -- letting you plug in any I/O backend without changing any mdnspp
internals.

Three built-in policies cover most use cases:

| Policy | Header | Use case |
|--------|--------|----------|
| `DefaultPolicy` | `<mdnspp/defaults.h>` | Standalone, no external dependencies |
| `AsioPolicy` | `<mdnspp/asio.h>` | Integration with ASIO (Boost.Asio or standalone Asio) |
| `MockPolicy` | `<mdnspp/testing/mock_policy.h>` | Unit testing without network access |

## Primer

All five mdnspp `basic_*` types are parameterized on `Policy`:

```cpp
template <Policy P>
class basic_observer;

template <Policy P>
class basic_querier;

template <Policy P>
class basic_service_discovery;

template <Policy P>
class basic_service_server;

template <Policy P, typename Clock = std::chrono::steady_clock>
class basic_service_monitor;
```

A `Policy` struct must provide:

1. `executor_type` -- the executor associated type
2. `socket_type` -- satisfies `SocketLike<socket_type>`
3. `timer_type` -- satisfies `TimerLike<timer_type>`
4. A static `post(executor_type, move_only_function<void()>)` function

All `basic_*` classes construct their socket and timer from the executor.
That constructor form (e.g., `socket_type{ex}`) must be available.

See [policies.md](policies.md) for DefaultPolicy, AsioPolicy, and MockPolicy
usage examples and the `post()` threading model.

## In-Depth

### Full concept requirements

#### Policy concept

```cpp
template <typename P>
concept Policy = requires
    {
        typename P::executor_type;
        typename P::socket_type;
        typename P::timer_type;
    }
    && SocketLike<typename P::socket_type>
    && TimerLike<typename P::timer_type>
    && std::constructible_from<typename P::socket_type, typename P::executor_type>
    && std::constructible_from<typename P::timer_type, typename P::executor_type>
    && std::constructible_from<typename P::socket_type, typename P::executor_type, std::error_code&>
    && std::constructible_from<typename P::timer_type, typename P::executor_type, std::error_code&>
    && std::constructible_from<typename P::socket_type, typename P::executor_type, const socket_options&>
    && std::constructible_from<typename P::socket_type, typename P::executor_type, const socket_options&, std::error_code&>
    && requires(typename P::executor_type ex, detail::move_only_function<void()> fn)
    {
        P::post(ex, std::move(fn));
    };
```

All four socket constructor forms are required to support both throwing and
non-throwing construction, with and without explicit `socket_options`.

#### SocketLike concept

```cpp
template <typename S>
concept SocketLike = requires(
    S &s,
    const endpoint &ep,
    std::span<const std::byte> send_data,
    std::error_code &ec,
    std::function<void(const endpoint &, std::span<std::byte>)> handler)
{
    { s.async_receive(handler) } -> std::same_as<void>;
    { s.send(ep, send_data) }    -> std::same_as<void>;
    { s.send(ep, send_data, ec)} -> std::same_as<void>;
    { s.close() }                -> std::same_as<void>;
};
```

`async_receive` delivers packets by calling `handler(sender, data)` for each
received datagram. It is expected to re-arm itself internally (i.e., it keeps
listening until `close()` is called).

`send` has two overloads: one that throws or ignores errors internally, and one
that reports errors via the `std::error_code&` out-parameter.

#### TimerLike concept

```cpp
template <typename T>
concept TimerLike = requires(
    T &t,
    std::chrono::milliseconds dur,
    std::function<void(std::error_code)> handler)
{
    t.expires_after(dur);
    { t.async_wait(handler) } -> std::same_as<void>;
    { t.cancel() }            -> std::same_as<void>;
};
```

`expires_after` sets the timer deadline (no return constraint; ASIO timers
return `std::size_t`). `async_wait` calls `handler` when the timer fires or is
cancelled. `cancel` stops a pending wait immediately with an error code.

---

### Implementing a minimal custom Policy

The following shows a minimal Policy that wraps a hypothetical custom event
loop. It is illustrative -- real implementations will follow the pattern of
`DefaultPolicy` or `AsioPolicy`.

**Step 1: Define executor, socket, and timer types**

Your socket must satisfy `SocketLike`, your timer must satisfy `TimerLike`, and
both must be constructible from your executor type.

```cpp
// Forward declarations
struct MyExecutor;
struct MySocket;
struct MyTimer;
```

**Step 2: Implement MySocket**

```cpp
struct MySocket
{
    // Constructors required by Policy concept
    explicit MySocket(MyExecutor ex);
    MySocket(MyExecutor ex, std::error_code &ec);
    MySocket(MyExecutor ex, const mdnspp::socket_options &opts);
    MySocket(MyExecutor ex, const mdnspp::socket_options &opts, std::error_code &ec);

    // SocketLike interface
    void async_receive(
        std::function<void(const mdnspp::endpoint &, std::span<std::byte>)> handler);

    void send(const mdnspp::endpoint &ep, std::span<const std::byte> data);
    void send(const mdnspp::endpoint &ep, std::span<const std::byte> data,
              std::error_code &ec);

    void close();
};
```

Inside `async_receive`, schedule your custom I/O loop to call `handler` for
each incoming packet and re-arm automatically.

**Step 3: Implement MyTimer**

```cpp
struct MyTimer
{
    explicit MyTimer(MyExecutor ex);
    MyTimer(MyExecutor ex, std::error_code &ec);

    void expires_after(std::chrono::milliseconds duration);
    void async_wait(std::function<void(std::error_code)> handler);
    void cancel();
};
```

**Step 4: Define the Policy struct**

```cpp
struct MyPolicy
{
    using executor_type = MyExecutor;
    using socket_type   = MySocket;
    using timer_type    = MyTimer;

    static void post(executor_type ex,
                     mdnspp::detail::move_only_function<void()> fn)
    {
        ex.schedule(std::move(fn)); // schedule on your event loop
    }
};
```

**Step 5: Use the custom Policy**

```cpp
MyExecutor ex{...};

mdnspp::basic_observer<MyPolicy> obs{ex,
    mdnspp::observer_options{
        .on_record = [](const auto &, const auto &) { ... }
    }
};

obs.async_observe([](std::error_code ec) { ... });
ex.run();
```

---

### post() contract

`post()` must be thread-safe. mdnspp calls it from arbitrary threads (e.g., when
`watch()` or `unwatch()` are called from a background thread). The posted
function must execute on the correct executor thread -- the same thread that
drives the event loop.

Internally, every `post()` call goes through a `std::weak_ptr<bool>` guard. If
the `basic_*` object has been destroyed before the posted work executes, the
guard check fails silently and the work is discarded.

---

### When to use a custom Policy

Custom policies are most useful when:

- **Embedding in an existing event loop.** A game engine, GUI framework, or
  service daemon may have its own event loop that cannot be blocked. Wrap your
  loop's async primitives in a custom Policy to drive mdnspp without spawning
  threads or running a separate loop.

- **Custom logging or monitoring.** Wrap a real socket/timer pair to intercept
  every send/receive for diagnostic purposes.

- **Alternative I/O libraries.** If you use libuv, libev, libevent, or another
  event library, a custom Policy bridges that library to mdnspp without any
  mdnspp changes.

- **Strict testability.** MockPolicy is provided for unit testing, but a custom
  Policy can add richer injection capabilities (packet recording, simulated
  latency, error injection).

---

### DefaultPolicy and AsioPolicy as examples

- `DefaultPolicy` source: `lib/mdnspp/include/mdnspp/detail/default_policy.h`
- `AsioPolicy` source: `lib/mdnspp/asio/include/mdnspp/asio_policy.h`

Both are real, production Policy implementations and are the best reference
for building your own.

## See Also

- [policies.md](policies.md) -- DefaultPolicy, AsioPolicy, and MockPolicy usage
- [API reference: policy.h](api/observer.md) -- SocketLike and TimerLike concept definitions
- [Async Patterns](async-patterns.md) -- ASIO completion token forms (AsioPolicy)
