#ifndef HPP_GUARD_MDNSPP_NATIVE_NATIVE_POLICY_H
#define HPP_GUARD_MDNSPP_NATIVE_NATIVE_POLICY_H

// NativePolicy — traits struct bundling NativeContext + NativeSocket + NativeTimer.
// Satisfies Policy<P>: executor_type, socket_type, timer_type all present with
// the required constructors (throwing and error_code overloads).
//
// No ASIO includes. Include <mdnspp/native.h> for the full umbrella.

#include "mdnspp/policy.h"
#include "mdnspp/native/native_context.h"
#include "mdnspp/native/native_socket.h"
#include "mdnspp/native/native_timer.h"

namespace mdnspp {

struct NativePolicy
{
    using executor_type = NativeContext &;
    using socket_type   = NativeSocket;
    using timer_type    = NativeTimer;
};

} // namespace mdnspp

static_assert(mdnspp::Policy<mdnspp::NativePolicy>,
              "NativePolicy must satisfy Policy — check NativeSocket/NativeTimer constructor signatures");

#endif
