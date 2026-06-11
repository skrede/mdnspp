# Custom Policies

Every `basic_*` class template in mdnspp is parameterized on a policy. A
policy is a struct (or class) that provides an executor type, a socket type, and
a timer type &mdash; letting you plug in any I/O backend without changing any mdnspp
internals.

Four built-in policies cover most use cases:

| Policy | Header | Use case |
|--------|--------|----------|
| `default_policy` | `<mdnspp/defaults.h>` | Standalone, no external dependencies |
| `asio_policy` | `<mdnspp/asio.h>` | Integration with ASIO (Boost.Asio or standalone Asio) |
| `mock_policy` | `<mdnspp/testing/mock_policy.h>` | Unit testing without network access |
| `inproc_policy` | `<mdnspp/inproc/inproc_policy.h>` | In-process multicast simulation |

## Primer

All mdnspp `basic_*` types are on a policy type satisfying `policy_like`:

```cpp
template <policy_like P>
class basic_observer;

template <policy_like P>
class basic_querier;

template <policy_like P>
class basic_service_discovery;

template <policy_like P>
class basic_service_server;

template <policy_like P, typename Clock = std::chrono::steady_clock>
class basic_service_monitor;

template <policy_like P>
class basic_nic_monitor;

template <policy_like P, template <typename...> class... Peers>
class basic_nic_group;
```

A policy struct must provide:

1. `executor_type` &mdash; the executor associated type
2. `socket_type` &mdash; satisfies `socket_like<socket_type>`
3. `timer_type` &mdash; satisfies `timer_like<timer_type>`
4. A static `post(executor_type, move_only_function<void()>)` function

All `basic_*` classes construct their socket and timer from the executor.
That constructor form (e.g., `socket_type{ex}`) must be available.

An optional fifth member is supported:

5. `socket_options_type` &mdash; a type derived from `socket_options` that the `basic_*` constructors accept instead of the base `socket_options` when present. Detected via the `policy_socket_options_t<P>` trait. Policies without this member use the base `socket_options` (the default). `encrypted_policy<Inner>` sets this to `encrypt_socket_options`.

See [policies.md](policies.md) for default_policy, asio_policy, and mock_policy
usage examples and the `post()` threading model.

## In-Depth

### Full concept requirements

#### The policy_like concept

```cpp
// policy_like<P>: the unified policy concept.
// A policy bundles an executor type with a socket type and timer type,
// both constructible from the executor (matching ASIO convention).
//
// Semantic requirements (not expressible in the concept):
//   - P::post(ex, fn) must be callable from any thread; the peers use it to
//     marshal stop()/update_* requests onto the executor.
//   - Work posted via P::post runs on the executor, serialized with socket
//     receive handlers and timer wait handlers.
template <typename P>
concept policy_like = requires
    {
        typename P::executor_type;
        typename P::socket_type;
        typename P::timer_type;
    }
    && socket_like<typename P::socket_type>
    && timer_like<typename P::timer_type>
    && std::constructible_from<typename P::socket_type, typename P::executor_type>
    && std::constructible_from<typename P::timer_type, typename P::executor_type>
    && std::constructible_from<typename P::socket_type, typename P::executor_type, std::error_code&>
    && std::constructible_from<typename P::timer_type, typename P::executor_type, std::error_code&>
    && std::constructible_from<typename P::socket_type, typename P::executor_type, const policy_socket_options_t<P>&>
    && std::constructible_from<typename P::socket_type, typename P::executor_type, const policy_socket_options_t<P>&, std::error_code&>
    && requires(typename P::executor_type ex, move_only_function<void()> fn)
    {
        P::post(ex, std::move(fn));
    };
```

All four socket constructor forms are required to support both throwing and
non-throwing construction, with and without explicit socket options. The
socket-options constraints use `policy_socket_options_t<P>`: when the policy
declares a `socket_options_type` derived from `socket_options`, that type is
required; otherwise the base `socket_options` is.

#### socket_like concept

```cpp
// socket_like<S>: satisfied by any type that provides the mDNS socket interface.
// The receive handler is invoked with the error code first (asio convention);
// on error the metadata is empty and the data span is empty.
//
// Semantic requirements (not expressible in the concept):
//   - Receive handlers fire on the policy executor; the library never locks
//     around handler invocation and relies on executor serialization.
//   - close() releases the pending receive handler; after close() no handler
//     may fire.
template <typename S>
concept socket_like = requires(S &s, const endpoint &ep, std::span<const std::byte> send_data, std::error_code &ec, move_only_function<void(std::error_code, const recv_metadata &, std::span<std::byte>)> handler)
{
    { s.async_receive(std::move(handler)) } -> std::same_as<void>;
    { s.send(ep, send_data) } -> std::same_as<void>;
    { s.send(ep, send_data, ec) } -> std::same_as<void>;
    { s.close() } -> std::same_as<void>;
};
```

`async_receive` delivers packets by calling `handler(ec, metadata, data)` for
each received datagram, error code first. On success `ec` is falsy,
`metadata` is a `recv_metadata` containing the sender endpoint, the optional
IP TTL, and the receiving interface index, and `data` spans the payload. On
error `ec` carries the failure, the metadata is empty, and the data span is
empty. The socket is expected to re-arm itself internally (i.e., it keeps
listening until `close()` is called), and after `close()` no handler may
fire.

`send` has two overloads: one that throws or ignores errors internally, and one
that reports errors via the `std::error_code&` out-parameter.

#### timer_like concept

```cpp
// timer_like<T>: satisfied by any type that provides the mDNS timer interface.
//
// Semantic requirements (not expressible in the concept):
//   - cancel() completes every pending async_wait with an error code equal to
//     operation_aborted/operation_canceled; every stop() path waits on this.
//   - expires_after() on a timer with a pending wait also cancels that wait.
//   - Wait handlers fire on the policy executor.
template <typename T>
concept timer_like = requires(T &t, std::chrono::milliseconds dur, move_only_function<void(std::error_code)> handler)
{
    t.expires_after(dur); // no return constraint — asio::steady_timer returns std::size_t
    { t.async_wait(std::move(handler)) } -> std::same_as<void>;
    { t.cancel() } -> std::same_as<void>;
};
```

`expires_after` sets the timer deadline (no return constraint; ASIO timers
return `std::size_t`) and cancels a pending wait. `async_wait` calls
`handler` when the timer fires or is cancelled. `cancel` completes every
pending wait with `operation_aborted` / `operation_canceled` — every
`stop()` path in the library waits on this guarantee.

---

### Implementing a minimal custom policy

The following shows a minimal policy that wraps a hypothetical custom event
loop. It is illustrative &mdash; real implementations will follow the pattern of
`default_policy` or `asio_policy`.

**Step 1: Define executor, socket, and timer types**

Your socket must satisfy `socket_like`, your timer must satisfy `timer_like`, and
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
    // Constructors required by the policy_like concept
    explicit MySocket(MyExecutor ex);
    MySocket(MyExecutor ex, std::error_code &ec);
    MySocket(MyExecutor ex, const mdnspp::socket_options &opts);
    MySocket(MyExecutor ex, const mdnspp::socket_options &opts, std::error_code &ec);

    // socket_like interface -- handler is invoked with the error code first
    void async_receive(
        mdnspp::move_only_function<void(std::error_code, const mdnspp::recv_metadata &, std::span<std::byte>)> handler);

    void send(const mdnspp::endpoint &ep, std::span<const std::byte> data);
    void send(const mdnspp::endpoint &ep, std::span<const std::byte> data,
              std::error_code &ec);

    void close();
};
```

Inside `async_receive`, schedule your custom I/O loop to call
`handler({}, metadata, data)` for each incoming packet and re-arm
automatically. Fatal receive failures are reported by invoking the handler
with the error code and empty metadata/data; after `close()` no handler may
fire.

**Step 3: Implement MyTimer**

```cpp
struct MyTimer
{
    explicit MyTimer(MyExecutor ex);
    MyTimer(MyExecutor ex, std::error_code &ec);

    void expires_after(std::chrono::milliseconds duration);
    void async_wait(mdnspp::move_only_function<void(std::error_code)> handler);
    void cancel();
};
```

**Step 4: Define the policy struct**

```cpp
struct MyPolicy
{
    using executor_type = MyExecutor;
    using socket_type   = MySocket;
    using timer_type    = MyTimer;

    static void post(executor_type ex,
                     mdnspp::move_only_function<void()> fn)
    {
        ex.schedule(std::move(fn)); // schedule on your event loop
    }
};
```

**Step 5: Use the custom policy**

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
function must execute on the correct executor thread &mdash; the same thread that
drives the event loop.

Internally, every `post()` call goes through a `std::weak_ptr<bool>` guard. If
the `basic_*` object has been destroyed before the posted work executes, the
guard check fails silently and the work is discarded.

---

### When to use a custom policy

Custom policies are most useful when:

- **Embedding in an existing event loop.** A game engine, GUI framework, or
  service daemon may have its own event loop that cannot be blocked. Wrap your
  loop's async primitives in a custom policy to drive mdnspp without spawning
  threads or running a separate loop.

- **Custom logging or monitoring.** Wrap a real socket/timer pair to intercept
  every send/receive for diagnostic purposes.

- **Alternative I/O libraries.** If you use libuv, libev, libevent, or another
  event library, a custom policy bridges that library to mdnspp without any
  mdnspp changes.

- **Strict testability.** mock_policy is provided for unit testing, but a custom
  policy can add richer injection capabilities (packet recording, simulated
  latency, error injection).

---

### inproc_policy as a worked example

`inproc_policy` is the clearest in-tree example of how to satisfy the `policy_like`
concept with a custom executor model. Source:
`lib/mdnspp-inproc/include/mdnspp/inproc/inproc_policy.h`

```cpp
template <typename Clock = std::chrono::steady_clock>
struct inproc_policy
{
    using executor_type = inproc_executor<Clock> &;
    using socket_type   = inproc_socket<Clock>;
    using timer_type    = inproc_timer<Clock>;

    static void post(executor_type ex, detail::move_only_function<void()> fn)
    {
        ex.post(std::move(fn));
    }
};
```

**`executor_type = inproc_executor<Clock>&`**

The executor is a reference, not a value. This is the same pattern as
`asio_policy` (whose `executor_type` is `asio::io_context&`). Every `basic_*`
component stores the reference and constructs its socket and timer from it.
The `inproc_bus` is not part of `executor_type` directly — it is reachable via
`ex.bus()`.

`default_policy` follows the same pattern: its `executor_type` is
`default_context&`, a reference to an externally owned context.
`inproc_policy` likewise requires an externally constructed `inproc_executor`
because the bus must be shared across all components and its lifetime must
outlast all of them.

**`socket_type = inproc_socket<Clock>`**

`inproc_socket<Clock>` satisfies `socket_like`. On construction it registers
itself with the bus via `ex.bus().register_socket(...)` and receives an
assigned `127.0.0.1:NNNN` endpoint. `send()` enqueues packets onto the bus
queue rather than delivering inline — this prevents re-entrancy when a receive
callback triggers a send. `async_receive()` stores the handler; `deliver()` is
called by the bus when a packet arrives for this socket's endpoint.

**`timer_type = inproc_timer<Clock>`**

`inproc_timer<Clock>` satisfies `timer_like`. On construction it registers with
`ex.register_timer(this)`. `expires_after()` sets the deadline; `try_fire(now)`
is called by the executor on each `step()` and fires the stored handler if the
deadline has passed.

**`post()` threading model**

`inproc_policy::post()` delegates to `ex.post()`, which appends to a
`std::deque`. This is simpler than `default_policy` (which uses a mutex-protected
queue) because `inproc_executor` is single-threaded by design — it is not safe to
call `post()` from a thread other than the one driving `run()` unless the caller
handles synchronisation externally.

**Bus parameter vs. context model**

The key structural difference from `default_policy`: `inproc_policy` separates the
shared medium (the bus) from the executor. Multiple components sharing the same
bus can be driven by a single executor, but the bus itself is not owned by the
executor — it is passed in by reference. This makes it straightforward to test
multi-party scenarios where components need to exchange packets without any real
network.

See [inproc-bus.md](inproc-bus.md) for the full production usage guide.

### default_policy and asio_policy as examples

- `default_policy` source: `lib/mdnspp/include/mdnspp/default/default_policy.h`
- `asio_policy` source: `lib/mdnspp-asio/include/mdnspp/asio/asio_policy.h`

Both are real, production policy implementations and are the best reference
for building your own.

## See Also

- [policies.md](policies.md) &mdash; default_policy, asio_policy, and mock_policy usage; the policy_like concept and recv_metadata
- `lib/mdnspp/include/mdnspp/policy.h` &mdash; authoritative socket_like, timer_like, and policy_like concept definitions
- [Async Patterns](async-patterns.md) -- ASIO completion token forms (asio_policy)
