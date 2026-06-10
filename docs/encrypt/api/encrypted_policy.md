# encrypted_policy

Composable policy wrapper that substitutes `encrypted_socket` for the inner policy's socket type. Satisfies the `policy_like` concept, so any `basic_*` class template that accepts a policy works with `encrypted_policy<Inner>` without modification.

## Header and Alias

| Form | Header |
|------|--------|
| `encrypted_policy<Inner>` | `#include <mdnspp/encrypt/encrypted_policy.h>` |

```cpp
template <policy_like Inner>
struct encrypted_policy;
```

## Template Parameters

| Parameter | Constraint | Description |
|-----------|------------|-------------|
| `Inner` | satisfies `policy_like` | The underlying policy providing the executor, timer, and inner socket. Typically `default_policy`, `asio_policy`, or `inproc_policy`. |

## Type Aliases

```cpp
using executor_type       = typename Inner::executor_type;
using socket_type         = encrypted_socket<typename Inner::socket_type>;
using timer_type          = typename Inner::timer_type;
using socket_options_type = encrypt_socket_options;
```

| Alias | Value | Description |
|-------|-------|-------------|
| `executor_type` | `Inner::executor_type` | Forwarded from the inner policy unchanged. |
| `socket_type` | `encrypted_socket<Inner::socket_type>` | The inner socket type wrapped in `encrypted_socket`. The `basic_*` types construct this type from the executor via `encrypted_socket`'s forwarding constructors. |
| `timer_type` | `Inner::timer_type` | Forwarded from the inner policy unchanged. |
| `socket_options_type` | `encrypt_socket_options` | Detected by `policy_socket_options_t<P>` so that `basic_*` types construct the socket with `encrypt_socket_options` instead of the base `socket_options`. |

## Static Methods

### post

```cpp
static void post(executor_type ex, detail::move_only_function<void()> fn);
```

Delegates directly to `Inner::post(ex, std::move(fn))`. Thread-safe work scheduling semantics are identical to those of the inner policy.

## Policy Conformance

`encrypted_policy<Inner>` satisfies the `policy_like` concept because:

- `executor_type`, `socket_type`, and `timer_type` are present.
- `socket_type` (`encrypted_socket<Inner::socket_type>`) satisfies `socket_like`.
- `timer_type` satisfies `timer_like` (same type as `Inner::timer_type`).
- `socket_type` is constructible from `(executor_type)`, `(executor_type, std::error_code&)`, `(executor_type, const socket_options&)`, and `(executor_type, const socket_options&, std::error_code&)` via the four `encrypted_socket` constructors.
- `post()` is a valid static call with the required signature.

The optional `socket_options_type` member causes `policy_socket_options_t<encrypted_policy<Inner>>` to resolve to `encrypt_socket_options`, enabling the `basic_*` types to pass encryption parameters to the socket on construction.

## Usage Example

```cpp
#include <mdnspp/encrypt/encrypted_policy.h>
#include <mdnspp/encrypt/encrypt_socket_options.h>
#include <mdnspp/default/default_policy.h>
#include <mdnspp/basic_observer.h>

// Construct an observer using the encrypted policy over default_policy
mdnspp::encrypt::encrypt_socket_options opts;
opts.encrypt.psk       = mdnspp::encrypt::secure_key{my_key};
opts.encrypt.sender_id = 1;

mdnspp::context ctx;
mdnspp::basic_observer<mdnspp::encrypt::encrypted_policy<mdnspp::default_policy>> obs{
    ctx,
    mdnspp::observer_options{},
    opts
};
obs.async_observe();
ctx.run();
```

For convenience aliases that avoid the angle-bracket form, see [defaults](defaults.md).

## See Also

- [encrypted_socket](encrypted_socket.md) -- the socket type substituted by this policy
- [encrypt_socket_options](encrypt_socket_options.md) -- options type detected via `socket_options_type`
- [defaults](defaults.md) -- convenience aliases (`encrypted_observer`, etc.) using `encrypted_policy<default_policy>`
- [Custom Policies](../../custom-policies.md) -- policy_like concept requirements
